#include "atclient/atclient.h"
#include "atchops/base64.h"
#include "atchops/rsa.h"
#include "atchops/hex.h"
#include "atclient/atclient.h"

#include "atclient/atclient_utils.h"
#include "atclient/atkeys.h"
#include "atclient/connection.h"
#include "atclient/connection_hooks.h"
#include "atclient/constants.h"
#include "atclient/request_options.h"
#include "atclient/string_utils.h"
#include "atlogger/atlogger.h"
#include <cJSON.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define HOST_BUFFER_SIZE 1024  // the size of the buffer for the host name for root and secondary
#define CRAM_SECRET_LENGTH 128 // hex encoded string
#define SHA_512_DIGEST_SIZE 64 // standard SHA-512 digest len in bytes
#define TAG "atclient"

static void atclient_set_atsign_initialized(atclient *ctx, const bool initialized);
static void atclient_set_atserver_connection_started(atclient *ctx, const bool started);
static int atclient_pkam_authenticate_validate_arguments(const atclient *ctx, const atclient_atkeys *atkeys,
                                                         const char *atsign);
static int atclient_cram_authenticate_validate_arguments(const atclient *ctx, const unsigned char *secret,
                                                         const char *atsign);

void atclient_init(atclient *ctx) {
  /*
   * 1. Validate arguments
   */
  if (ctx == NULL) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "ctx is NULL\n");
    return;
  }

  /*
   * 2. Initialize
   */
  memset(ctx, 0, sizeof(atclient));
}

void atclient_free(atclient *ctx) {
  /*
   * 1. Validate arguments
   */
  if (ctx == NULL) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "ctx is NULL\n");
    return;
  }

  /*
   * 2. Free
   */
  if (atclient_is_atsign_initialized(ctx)) {
    atclient_unset_atsign(ctx);
  }

  if (atclient_is_atserver_connection_started(ctx)) {
    atclient_stop_atserver_connection(ctx);
  }
}

int atclient_set_atsign(atclient *ctx, const char *atsign) {
  int ret = 1;

  /*
   * 1. Validate arguments
   */
  if (ctx == NULL) {
    ret = 1;
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "ctx is NULL\n");
    return ret;
  }

  /*
   * 2. Unset the atsign if it is already initialized
   */
  if (atclient_is_atsign_initialized(ctx)) {
    atclient_unset_atsign(ctx);
  }

  /*
   * 3. Set the atsign
   */
  const size_t atsign_len = strlen(atsign);
  const size_t atsign_size = atsign_len + 1;
  if ((ctx->atsign = malloc(sizeof(char) * atsign_size)) == NULL) {
    ret = 1;
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "Failed to allocate memory for atsign\n");
    goto exit;
  }

  memcpy(ctx->atsign, atsign, atsign_len);
  ctx->atsign[atsign_len] = '\0';

  /*
   * 4. Set the atsign initialized flag
   */
  atclient_set_atsign_initialized(ctx, true);

  ret = 0;
  goto exit;
exit: { return ret; }
}

void atclient_unset_atsign(atclient *ctx) {
  if (atclient_is_atsign_initialized(ctx)) {
    free(ctx->atsign);
  }
  ctx->atsign = NULL;
  atclient_set_atsign_initialized(ctx, false);
}

bool atclient_is_atserver_connection_started(const atclient *ctx) {
  return ctx->_initialized_fields[ATCLIENT_ATSERVER_CONNECTION_INDEX] & ATCLIENT_ATSERVER_CONNECTION_INITIALIZED;
}

int atclient_start_atserver_connection(atclient *ctx, const char *secondary_host, const int secondary_port) {
  int ret = 1; // error by default

  /*
   * 1. Validate arguments
   */
  if (ctx == NULL) {
    ret = 1;
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "ctx is NULL\n");
    return ret;
  }

  // remove hooks to preserve them across resets
  atclient_connection_hooks *conn_hooks = ctx->atserver_connection.hooks;

  // clear the atserver connection
  atclient_stop_atserver_connection(ctx);

  // (re) initialize the atserver connection
  atclient_connection_init(&(ctx->atserver_connection), ATCLIENT_CONNECTION_TYPE_ATSERVER);

  // add back hooks
  ctx->atserver_connection.hooks = conn_hooks;

  if ((ret = atclient_connection_connect(&(ctx->atserver_connection), secondary_host, secondary_port)) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atclient_connection_connect: %d\n", ret);
    goto exit;
  }

  atclient_set_atserver_connection_started(ctx, true);

  ret = 0;
  goto exit;

exit: { return ret; }
}

void atclient_stop_atserver_connection(atclient *ctx) {
  /*
   * 1. Validate arguments
   */
  if (ctx == NULL) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "ctx is NULL\n");
    return;
  }

  /*
   * 2. Stop the atserver connection
   */
  if (atclient_is_atserver_connection_started(ctx)) {
    atclient_connection_free(&(ctx->atserver_connection));
  }
  memset(&(ctx->atserver_connection), 0, sizeof(atclient_connection));
  atclient_set_atserver_connection_started(ctx, false);
}

bool atclient_is_atsign_initialized(const atclient *ctx) {
  /*
   * 1. Validate arguments
   */
  if (ctx == NULL) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "ctx is NULL\n");
    return false;
  }

  return ctx->_initialized_fields[ATCLIENT_ATSIGN_INDEX] & ATCLIENT_ATSIGN_INITIALIZED;
}

int atclient_pkam_authenticate(atclient *ctx, const char *atsign, const atclient_atkeys *atkeys,
                               atclient_authenticate_options *options) {

  int ret = 1; // error by default

  /*
   * 1. Validate arguments
   */
  if ((ret = atclient_pkam_authenticate_validate_arguments(ctx, atkeys, atsign)) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atclient_pkam_authenticate_validate_arguments: %d\n", ret);
    return ret;
  }

  /*
   * 2. Initialize variables
   */

  // free later
  char *root_cmd = NULL;
  char *from_cmd = NULL;
  char *pkam_cmd = NULL;
  char *atsign_with_at = NULL;

  char *atserver_host = NULL;
  int atserver_port = 0;

  const size_t recvsize = 1024; // sufficient buffer size to receive 1. host & port from atDirectory, 2. challenge from
                                // `from:` noop_cmd, 3. pkam success message from `pkam:` noop_cmd
  unsigned char recv[recvsize];
  memset(recv, 0, sizeof(unsigned char) * recvsize);
  size_t recv_len;

  const size_t challenge_size = 256; // sufficient buffer size to hold the challenge received from `from:` noop_cmd
  char challenge[challenge_size];
  memset(challenge, 0, sizeof(char) * challenge_size);
  size_t challenge_len = 0;

  const size_t signature_size = 256; // RSA-2048 signature always generates a 256 byte signature
  unsigned char signature[signature_size];
  memset(signature, 0, sizeof(unsigned char) * signature_size);

  const size_t signature_base64_size = atchops_base64_encoded_size(signature_size);
  unsigned char signature_base64[signature_base64_size];
  memset(signature_base64, 0, sizeof(unsigned char) * signature_base64_size);
  size_t signature_base64_len = 0;

  /*
   * 3. Ensure that the atsign has the @ symbol.
   */
  if ((ret = atclient_string_utils_atsign_with_at(atsign, &(atsign_with_at))) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atclient_string_utils_atsign_with_at: %d\n", ret);
    goto exit;
  }

  const char *atsign_without_at = (atsign_with_at + 1);

  /*
   * 4. Get atserver_host and atserver_port
   */
  bool should_free_atserver_host = false;
  if (options != NULL) {
    if (atclient_authenticate_options_is_atdirectory_host_initialized(options) &&
        atclient_authenticate_options_is_atdirectory_port_initialized(options)) {
      atserver_host = options->atdirectory_host;
      atserver_port = options->atdirectory_port;
    }
  }

  if (atserver_host == NULL || atserver_port == 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_INFO,
                 "Missing atServer host or port. Using production atDirectory to look up atServer host and port\n");
    if ((ret = atclient_utils_find_atserver_address(ATCLIENT_ATDIRECTORY_PRODUCTION_HOST,
                                                    ATCLIENT_ATDIRECTORY_PRODUCTION_PORT, atsign, &atserver_host,
                                                    &atserver_port)) != 0) {
      atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atclient_utils_find_atserver_address: %d\n", ret);
      goto exit;
    }
    // only free this memory if it was allocated internally (by atclient_utils_find_atserver_address)
    should_free_atserver_host = true;
  }

  /*
   * 5. Start atServer connection (kill the existing connection if it exists)
   */
  if ((ret = atclient_start_atserver_connection(ctx, atserver_host, atserver_port)) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atclient_start_atserver_connection: %d\n", ret);
    goto exit;
  }

  /*
   * 6a. Build `from:` cmd
   */
  const size_t from_cmd_size =
      strlen("from:") + strlen(atsign_without_at) + strlen("\r\n") + 1; // "from:" has a length of 5
  if ((from_cmd = malloc(sizeof(char) * from_cmd_size)) == NULL) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "Failed to allocate memory for from_cmd\n");
    goto exit;
  }
  snprintf(from_cmd, from_cmd_size, "from:%s\r\n", atsign_without_at);

  /*
   * 6b. Send `from:` cmd
   */
  if ((ret = atclient_connection_send(&(ctx->atserver_connection), (unsigned char *)from_cmd, from_cmd_size - 1, recv,
                                      recvsize, &recv_len)) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atclient_connection_send: %d\n", ret);
    goto exit;
  }

  char *str_with_data_prefix = NULL;
  if (atclient_string_utils_get_substring_position((char *)recv, DATA_TOKEN, &str_with_data_prefix) != 0) {
    ret = 1;
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "recv was \"%.*s\" and did not have prefix \"data:\"\n",
                 (int)recv_len, recv);
    goto exit;
  }

  /*
   * 7. We got `data:<challenge>`
   *    Let us sign the challenge with RSA-2048 PKAM Private Key and Base64 Encode it
   */

  challenge_len = strlen(str_with_data_prefix) - strlen(DATA_TOKEN);
  memcpy(challenge, str_with_data_prefix + strlen(DATA_TOKEN), challenge_len); // +5 to skip the 'data:' prefix

  // sign
  if ((ret = atchops_rsa_sign(&atkeys->pkam_private_key, ATCHOPS_MD_SHA256, (unsigned char *)challenge, challenge_len,
                              signature)) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atchops_rsa_sign: %d\n", ret);
    goto exit;
  }

  // base64 encode it
  if ((ret = atchops_base64_encode(signature, signature_size, signature_base64, signature_base64_size,
                                   &signature_base64_len)) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atchops_base64_encode: %d\n", ret);
    goto exit;
  }

  /*
   * 8a. Build `pkam:` noop_cmd
   */
  size_t pkam_cmd_size = strlen("pkam:");
  if (atclient_atkeys_is_enrollment_id_initialized((atclient_atkeys *)atkeys) && atkeys->enrollment_id != NULL) {
    pkam_cmd_size += strlen("enrollmentId:") + strlen(atkeys->enrollment_id) + strlen(":");
  }
  pkam_cmd_size += signature_base64_len + strlen("\r\n") + 1;
  if ((pkam_cmd = malloc(sizeof(char) * pkam_cmd_size)) == NULL) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "Failed to allocate memory for pkam_cmd\n");
    goto exit;
  }
  size_t pos = 0;
  pos += snprintf(pkam_cmd + pos, pkam_cmd_size - pos, "pkam:");

  if (atclient_atkeys_is_enrollment_id_initialized((atclient_atkeys *)atkeys) && atkeys->enrollment_id != NULL) {
    pos += snprintf(pkam_cmd + pos, pkam_cmd_size - pos, "enrollmentId:%s:", atkeys->enrollment_id);
  }

  pos += snprintf(pkam_cmd + pos, pkam_cmd_size - pos, "%s\r\n", signature_base64);

  /*
   * 8b. Send `pkam:` noop_cmd
   */
  memset(recv, 0, sizeof(unsigned char) * recvsize);
  if ((ret = atclient_connection_send(&(ctx->atserver_connection), (unsigned char *)pkam_cmd, pkam_cmd_size - 1, recv,
                                      recvsize, &recv_len)) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atclient_connection_send: %d\n", ret);
    goto exit;
  }

  // check for data:success
  if (!atclient_string_utils_starts_with((char *)recv, "data:success")) {
    ret = 1;
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "recv was \"%.*s\" and did not have prefix \"data:success\"\n",
                 (int)recv_len, recv);
    goto exit;
  }

  /*
   * 9. Set up the atclient context
   */

  // initialize ctx->atsign.atsign and ctx->atsign.withour_prefix_str to the newly authenticated atSign
  if ((ret = atclient_set_atsign(ctx, atsign_with_at)) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atclient_set_atsign: %d\n", ret);
    goto exit;
  }

  // set atkeys
  ctx->atkeys = *atkeys;

  ret = 0;

  goto exit;
exit: {
  free(atsign_with_at);
  free(root_cmd);
  free(from_cmd);
  free(pkam_cmd);
  if (should_free_atserver_host) {
    free(atserver_host);
  }
  return ret;
}
}

int atclient_cram_authenticate(atclient *ctx, const char *atsign, const char *cram_secret,
                               atclient_authenticate_options *options) {
  int ret = 1; // error by default

  /*
   * 1. Validate arguments
   */
  if ((ret = atclient_cram_authenticate_validate_arguments(ctx, (unsigned char *)cram_secret, atsign)) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atclient_cram_authenticate_validate_arguments: %d\n", ret);
    return ret;
  }

  /*
   * 2. Initialize variables
   */

  // free later
  char *root_cmd = NULL;
  char *from_cmd = NULL;
  char *cram_cmd = NULL;
  char *atsign_with_at = NULL;

  char *atserver_host = NULL;
  int atserver_port = 0;

  const size_t recvsize = 1024; // sufficient buffer size to receive 1. host & port from atDirectory, 2. challenge from
                                // `from:` noop_cmd, 3. cram success message from `cram:` noop_cmd
  unsigned char recv[recvsize];
  memset(recv, 0, sizeof(unsigned char) * recvsize);
  size_t recv_len;

  const size_t challenge_size = 256; // sufficient buffer size to hold the challenge received from `from:` noop_cmd
  char challenge[challenge_size];
  memset(challenge, 0, sizeof(char) * challenge_size);

  const size_t digest_input_size = CRAM_SECRET_LENGTH + challenge_size;
  unsigned char digest_input[digest_input_size];
  memset(digest_input, 0, digest_input_size);
  size_t digest_input_len = 0; // actual length of data in digest_input

  unsigned char digest[SHA_512_DIGEST_SIZE];
  memset(digest, 0, sizeof(unsigned char) * SHA_512_DIGEST_SIZE);

  char *digest_hex_encoded;

  /*
   * 1. Ensure that the atsign has the @ symbol.
   */
  if ((ret = atclient_string_utils_atsign_with_at(atsign, &(atsign_with_at))) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atclient_string_utils_atsign_with_at: %d\n", ret);
    goto exit;
  }

  const char *atsign_without_at = atsign_with_at + 1;
  // Now we have two variables that we can use: `atsign_with_at` and `atsign_without_at`

  /*
   * 4. Get atserver_host and atserver_port
   */
  bool should_free_atserver_host = false;
  if (options != NULL) {
    if (atclient_authenticate_options_is_atdirectory_host_initialized(options) &&
        atclient_authenticate_options_is_atdirectory_port_initialized(options)) {
      atserver_host = options->atdirectory_host;
      atserver_port = options->atdirectory_port;
    }
  }

  if (atserver_host == NULL || atserver_port == 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_INFO,
                 "Missing atServer host or port. Using production atDirectory to look up atServer host and port\n");
    if ((ret = atclient_utils_find_atserver_address(ATCLIENT_ATDIRECTORY_PRODUCTION_HOST,
                                                    ATCLIENT_ATDIRECTORY_PRODUCTION_PORT, atsign, &atserver_host,
                                                    &atserver_port)) != 0) {
      atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atclient_utils_find_atserver_address: %d\n", ret);
      goto exit;
    }
    // only free this memory if it was allocated internally (by atclient_utils_find_atserver_address)
    should_free_atserver_host = true;
  }

  atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_INFO, "atserver_host: %s\n", atserver_host);
  atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_INFO, "atserver_port: %d\n", atserver_port);

  /*
   * 2. Start atServer connection (kill the existing connection if it exists)
   */
  if ((ret = atclient_start_atserver_connection(ctx, atserver_host, atserver_port)) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atclient_start_atserver_connection: %d\n", ret);
    goto exit;
  }

  /*
   * 3a. Build `from:` noop_cmd
   */
  const size_t from_cmd_size =
      strlen("from:") + strlen(atsign_without_at) + strlen("\r\n") + 1; // "from:" has a length of 5
  if ((from_cmd = malloc(sizeof(char) * from_cmd_size)) == NULL) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "Failed to allocate memory for from_cmd\n");
    goto exit;
  }
  snprintf(from_cmd, from_cmd_size, "from:%s\r\n", atsign_without_at);

  /*
   * 3b. Send `from:` noop_cmd
   */
  if ((ret = atclient_connection_send(&(ctx->atserver_connection), (unsigned char *)from_cmd, from_cmd_size - 1, recv,
                                      recvsize, &recv_len)) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atclient_connection_send: %d\n", ret);
    goto exit;
  }
  char *str_with_data_prefix = NULL;
  if (atclient_string_utils_get_substring_position((char *)recv, DATA_TOKEN, &str_with_data_prefix) != 0) {
    ret = 1;
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "recv was \"%.*s\" and did not have prefix \"data:\"\n",
                 (int)recv_len, recv);
    goto exit;
  }

  /*
   * 4. Move cram secret to digest_input
   *    CRAM digest-input will be of the form "CRAM secret + challenge from server"
   */
  memcpy(digest_input, cram_secret, CRAM_SECRET_LENGTH);
  digest_input_len = CRAM_SECRET_LENGTH;

  /*
   * 5. We got `data:<challenge>`, move this challenge into digest_input
   *
   */
  memcpy(digest_input + digest_input_len, str_with_data_prefix + strlen(DATA_TOKEN),
         recv_len - strlen(DATA_TOKEN)); // trims 'data:' from the response and copy the challenge into 'digest_input'
  digest_input_len += strlen(str_with_data_prefix) - strlen(DATA_TOKEN);

  /*
   * 6a. convert 'digest_input' to bytes using utf-8 encode
   */
  unsigned char *digest_input_bytes = NULL;
  size_t digest_input_bytes_len = 0;
  if ((ret = atchops_utf8_encode(digest_input, &digest_input_bytes, &digest_input_bytes_len))) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atchops_utf8_encode: %d\n", ret);
    ret = 1;
    goto exit;
  }

  /*
   * 6b. generate SHA512 digest using the utf8-encoded bytes
   */
  if ((ret = atchops_sha_hash(ATCHOPS_MD_SHA512, digest_input_bytes, digest_input_bytes_len, digest)) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atchops_sha_hash: %d\n", ret);
    goto exit;
  }
  /*
   * 6b. hex encode the digest generated in the previous step
   */
  size_t digest_hex_encoded_len = (SHA_512_DIGEST_SIZE * 2) + 1; // hex represents each byte with 2 characters + /0
  digest_hex_encoded = malloc(sizeof(char) * digest_hex_encoded_len);
  if (digest_hex_encoded == NULL) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "Failed to allocate memory for digest_hex_encoded\n");
    goto exit;
  }

  if ((ret = atchops_bytes_to_hex(digest_hex_encoded, digest_hex_encoded_len, digest, sizeof(digest))) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atchops_bytes_to_hex_string: %d\n", ret);
    goto exit;
  }
  /*
   * 7a. Build `cram:` noop_cmd
   */
  cram_cmd = malloc(sizeof(char) * CRAM_COMMAND_LEN + 1); // free later
  ret = snprintf(cram_cmd, CRAM_COMMAND_LEN + 1, "%s:%s\r\n", CRAM_PREFIX, digest_hex_encoded);
  cram_cmd[CRAM_COMMAND_LEN] = '\n';

  /*
   * 7b. Send `cram:` noop_cmd
   */
  memset(recv, 0, sizeof(unsigned char) * recvsize);
  atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_INFO, "build cram command: %s\n", cram_cmd);
  if ((ret = atclient_connection_send(&(ctx->atserver_connection), (unsigned char *)cram_cmd, CRAM_COMMAND_LEN, recv,
                                      recvsize, &recv_len)) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atclient_connection_send: %d\n", ret);
    goto exit;
  }

  // check for data:success
  if (!atclient_string_utils_starts_with((char *)recv, "data:success")) {
    ret = 1;
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "recv was \"%.*s\" and did not have prefix \"data:success\"\n",
                 (int)recv_len, recv);
    goto exit;
  }
  atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_INFO, "CRAM auth successful\n");

  /*
   * 8. Set up the atclient context
   */

  // initialize ctx->atsign.atsign and ctx->atsign.withour_prefix_str to the newly authenticated atSign
  if ((ret = atclient_set_atsign(ctx, atsign_with_at)) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atclient_set_atsign: %d\n", ret);
    goto exit;
  }

  ret = 0;

exit: {
  free(atsign_with_at);
  free(root_cmd);
  free(from_cmd);
  free(cram_cmd);
  return ret;
}
}

int atclient_send_heartbeat(atclient *heartbeat_conn) {
  int ret = -1;

  /*
   * 1. Validate arguments
   */
  if (heartbeat_conn == NULL) {
    ret = 1;
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "heartbeat_conn is NULL\n");
    return ret;
  }

  if (!atclient_is_atserver_connection_started(heartbeat_conn)) {
    ret = 1;
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atserver connection is not started\n");
    return ret;
  }

  if (!atclient_is_atsign_initialized(heartbeat_conn)) {
    ret = 1;
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atsign is not initialized\n");
    return ret;
  }

  /*
   * 2. Send `noop:` command
   */
  unsigned char *recv = NULL;

  const char *noop_cmd = "noop:0\r\n";
  const size_t noop_cmd_len = strlen(noop_cmd);

  const size_t recvsize = 64;
  if (!heartbeat_conn->async_read) {
    recv = malloc(sizeof(unsigned char) * recvsize);
    if (recv == NULL) {
      atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "Failed to allocate memory for recv\n");
      ret = 1;
      goto exit;
    }
    memset(recv, 0, sizeof(unsigned char) * recvsize);
  }
  size_t recv_len = 0;
  char *ptr = (char *)recv;

  if ((ret = atclient_connection_send(&heartbeat_conn->atserver_connection, (unsigned char *)noop_cmd, noop_cmd_len,
                                      recv, recvsize, &recv_len)) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "Failed to send noop noop_cmd: %d\n", ret);
    goto exit;
  }

  if (heartbeat_conn->async_read) {
    ret = 0;
    goto exit;
  }

  /*
   * 3. Parse response
   */
  if (strcmp(ptr, "data:ok") != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "Failed to receive heartbeat response\n");
    ret = -1;
    goto exit;
  }

  ret = 0;
  goto exit;
exit: {
  if (!heartbeat_conn->async_read) {
    free(recv);
  }
  return ret;
}
}

bool atclient_is_connected(atclient *ctx) { return atclient_connection_is_connected(&(ctx->atserver_connection)); }

void atclient_set_read_timeout(atclient *ctx, int timeout_ms) {
  mbedtls_ssl_conf_read_timeout(&(ctx->atserver_connection.ssl_config), timeout_ms);
}

static void atclient_set_atsign_initialized(atclient *ctx, const bool initialized) {
  if (initialized) {
    ctx->_initialized_fields[ATCLIENT_ATSIGN_INDEX] |= ATCLIENT_ATSIGN_INITIALIZED;
  } else {
    ctx->_initialized_fields[ATCLIENT_ATSIGN_INDEX] &= ~ATCLIENT_ATSIGN_INITIALIZED;
  }
}

static void atclient_set_atserver_connection_started(atclient *ctx, const bool started) {
  if (started) {
    ctx->_initialized_fields[ATCLIENT_ATSERVER_CONNECTION_INDEX] |= ATCLIENT_ATSERVER_CONNECTION_INITIALIZED;
  } else {
    ctx->_initialized_fields[ATCLIENT_ATSERVER_CONNECTION_INDEX] &= ~ATCLIENT_ATSERVER_CONNECTION_INITIALIZED;
  }
}

static int atclient_pkam_authenticate_validate_arguments(const atclient *ctx, const atclient_atkeys *atkeys,
                                                         const char *atsign) {
  int ret = 1;
  if (ctx == NULL) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "ctx is NULL\n");
    goto exit;
  }

  if (atsign == NULL || strlen(atsign) == 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atsign is NULL or the length is 0\n");
    goto exit;
  }

  ret = 0;
exit: { return ret; }
}

static int atclient_cram_authenticate_validate_arguments(const atclient *ctx, const unsigned char *secret,
                                                         const char *atsign) {
  int ret = 1;
  if (ctx == NULL) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "ctx is NULL\n");
    goto exit;
  }

  if (atsign == NULL || strlen(atsign) == 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atsign is NULL or the length is 0");
    goto exit;
  }

  if (secret == NULL || strlen(secret) < CRAM_SECRET_LENGTH) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "Invalid CRAM secret length");
    goto exit;
  }

  ret = 0;

exit: { return ret; }
}
