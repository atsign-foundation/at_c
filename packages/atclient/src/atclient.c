#include "atclient/atclient.h"
#include "atchops/base64.h"
#include "atchops/rsa.h"
#include "atclient/atclient.h"
#include "atclient/atclient_utils.h"
#include "atclient/atkeys.h"
#include "atclient/atsign.h"
#include "atclient/connection.h"
#include "atclient/constants.h"
#include "atclient/stringutils.h"
#include "atlogger/atlogger.h"
#include <cJSON.h>
#include <mbedtls/md.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define HOST_BUFFER_SIZE 1024 // the size of the buffer for the host name for root and secondary

#define TAG "atclient"

static void atclient_set_atsign_initialized(atclient *ctx, const bool initialized);
static void atclient_set_atserver_connection_started(atclient *ctx, const bool started);
static int atclient_pkam_authenticate_validate_arguments(const atclient *ctx, const char *atserver_host,
                                                         const int atserver_port, const atclient_atkeys *atkeys,
                                                         const char *atsign);

void atclient_init(atclient *ctx) {
  memset(ctx, 0, sizeof(atclient));
}

void atclient_free(atclient *ctx) {
  if (atclient_is_atsign_initialized(ctx)) {
    atclient_unset_atsign(ctx);
  }

  if(atclient_is_atserver_connection_started(ctx)) {
    atclient_stop_atserver_connection(ctx);
  }
}

int atclient_set_atsign(atclient *ctx, const char *atsign) {
  int ret = 1;

  if (atclient_is_atsign_initialized(ctx)) {
    atclient_unset_atsign(ctx);
  }

  const size_t atsign_len = strlen(atsign);
  const size_t atsign_size = atsign_len + 1;
  if ((ctx->atsign = malloc(sizeof(char) * atsign_size)) == NULL) {
    ret = 1;
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "Failed to allocate memory for atsign\n");
    goto exit;
  }

  memcpy(ctx->atsign, atsign, atsign_len);
  ctx->atsign[atsign_len] = '\0';

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

  // remove hooks to preserve them across resets
  atclient_connection_hooks *conn_hooks = ctx->atserver_connection.hooks;
  ctx->atserver_connection.hooks = NULL;

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
  if (atclient_is_atserver_connection_started(ctx)) {
    atclient_connection_free(&(ctx->atserver_connection));
  }
  memset(&(ctx->atserver_connection), 0, sizeof(atclient_connection));
  atclient_set_atserver_connection_started(ctx, false);
}

bool atclient_is_atsign_initialized(const atclient *ctx) {
  return ctx->_initialized_fields[ATCLIENT_ATSIGN_INDEX] & ATCLIENT_ATSIGN_INITIALIZED;
}

int atclient_pkam_authenticate(atclient *ctx, const char *atserver_host, const int atserver_port,
                               const atclient_atkeys *atkeys, const char *atsign) {

  int ret = 1; // error by default

  /*
   * 1. Validate arguments
   */
  if ((ret = atclient_pkam_authenticate_validate_arguments(ctx, atserver_host, atserver_port, atkeys, atsign)) != 0) {
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
  if ((ret = atclient_stringutils_atsign_with_at(atsign, &(atsign_with_at))) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atclient_stringutils_atsign_with_at: %d\n", ret);
    goto exit;
  }

  const char *atsign_without_at = (atsign_with_at + 1);

  // Now we have two variables that we can use: `atsign_with_at` and `atsign_without_at`

  /*
   * 4. Start atServer connection (kill the existing connection if it exists)
   */
  if ((ret = atclient_start_atserver_connection(ctx, atserver_host, atserver_port)) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atclient_start_atserver_connection: %d\n", ret);
    goto exit;
  }

  /*
   * 5a. Build `from:` noop_cmd
   */
  const size_t from_cmd_size =
      strlen("from:") + strlen(atsign_without_at) + strlen("\r\n") + 1; // "from:" has a length of 5
  if ((from_cmd = malloc(sizeof(char) * from_cmd_size)) == NULL) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "Failed to allocate memory for from_cmd\n");
    goto exit;
  }
  snprintf(from_cmd, from_cmd_size, "from:%s\r\n", atsign_without_at);

  /*
   * 5b. Send `from:` noop_cmd
   */
  if ((ret = atclient_connection_send(&(ctx->atserver_connection), (unsigned char *)from_cmd, from_cmd_size - 1, recv,
                                      recvsize, &recv_len)) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atclient_connection_send: %d\n", ret);
    goto exit;
  }

  if (!atclient_stringutils_starts_with((char *)recv, "data:")) {
    ret = 1;
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "recv was \"%.*s\" and did not have prefix \"data:\"\n",
                 (int)recv_len, recv);
    goto exit;
  }

  /*
   * 6. We got `data:<challenge>`
   *    Let us sign the challenge with RSA-2048 PKAM Private Key and Base64 Encode it
   */
  memcpy(challenge, recv, recv_len);
  // remove data:
  memmove(challenge, challenge + 5, recv_len - 5);
  challenge_len = recv_len - 5;

  // sign
  if ((ret = atchops_rsa_sign(atkeys->pkam_private_key, ATCHOPS_MD_SHA256, (unsigned char *)challenge, challenge_len,
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
   * 7a. Build `pkam:` noop_cmd
   */
  const size_t pkam_cmd_size = strlen("pkam:") + signature_base64_len + strlen("\r\n") + 1;
  if ((pkam_cmd = malloc(sizeof(char) * pkam_cmd_size)) == NULL) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "Failed to allocate memory for pkam_cmd\n");
    goto exit;
  }
  snprintf(pkam_cmd, pkam_cmd_size, "pkam:%s\r\n", signature_base64);

  /*
   * 7b. Send `pkam:` noop_cmd
   */
  memset(recv, 0, sizeof(unsigned char) * recvsize);
  if ((ret = atclient_connection_send(&(ctx->atserver_connection), (unsigned char *)pkam_cmd, pkam_cmd_size - 1, recv,
                                      recvsize, &recv_len)) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atclient_connection_send: %d\n", ret);
    goto exit;
  }

  // check for data:success
  if (!atclient_stringutils_starts_with((char *)recv, "data:success")) {
    ret = 1;
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "recv was \"%.*s\" and did not have prefix \"data:success\"\n",
                 (int)recv_len, recv);
    goto exit;
  }

  /*
   * 8. Set up the atclient context
   */

  // initialize ctx->atsign.atsign and ctx->atsign.withour_prefix_str to the newly authenticated atSign
  if((ret = atclient_set_atsign(ctx, atsign_with_at)) != 0) {
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
  return ret;
}
}

int atclient_send_heartbeat(atclient *heartbeat_conn) {
  int ret = -1;

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

  ret = atclient_connection_send(&heartbeat_conn->atserver_connection, (unsigned char *)noop_cmd, noop_cmd_len, recv,
                                 recvsize, &recv_len);
  if (ret != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "Failed to send noop noop_cmd: %d\n", ret);
    goto exit;
  } else if (heartbeat_conn->async_read) {
    goto exit;
  }

  if (!atclient_stringutils_starts_with((const char *)ptr, "data:ok") &&
      !atclient_stringutils_ends_with((const char *)ptr, "data:ok")) {
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

static int atclient_pkam_authenticate_validate_arguments(const atclient *ctx, const char *atserver_host,
                                                         const int atserver_port, const atclient_atkeys *atkeys,
                                                         const char *atsign) {
  int ret = 1;
  if (ctx == NULL) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "ctx is NULL\n");
    goto exit;
  }

  if (atserver_host == NULL) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atserver_host is NULL\n");
    goto exit;
  }

  if (atkeys == NULL) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atkeys is NULL\n");
    goto exit;
  }

  if (atsign == NULL || strlen(atsign) == 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atsign is NULL or the length is 0\n");
    goto exit;
  }

  ret = 0;
exit: { return ret; }
}