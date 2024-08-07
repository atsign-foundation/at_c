#include <atchops/aes_ctr.h>
#include <atchops/base64.h>
#include <atchops/iv.h>
#include <atclient/atclient.h>
#include <atclient/atkey.h>
#include <atclient/request_options.h>
#include <atclient/string_utils.h>
#include <atlogger/atlogger.h>
#include <stdlib.h>
#include <string.h>

#define TAG "atclient_put_self_key"

static int atclient_put_self_key_validate_arguments(atclient *ctx, atclient_atkey *atkey, const char *value);

int atclient_put_self_key(atclient *ctx, atclient_atkey *atkey, const char *value,
                          const atclient_put_self_key_request_options *request_options, int *commit_id) {
  int ret = 1;

  /*
   * 1. Validate arguments
   */
  if ((ret = atclient_put_self_key_validate_arguments(ctx, atkey, value)) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atclient_put_self_key_validate_arguments: %d\n", ret);
    return ret;
  }

  /*
   * 2. Variables
   */
  const size_t self_encryption_key_size = ATCHOPS_AES_256 / 8;
  unsigned char self_encryption_key[self_encryption_key_size];

  const size_t iv_size = ATCHOPS_IV_BUFFER_SIZE;
  unsigned char iv[iv_size];

  const size_t iv_base64_size = atchops_base64_encoded_size(iv_size) + 1;
  char iv_base64[iv_base64_size];

  const size_t value_len = strlen(value);

  const size_t value_encrypted_size = atchops_aes_ctr_ciphertext_size(value_len);
  unsigned char value_encrypted[value_encrypted_size];

  const size_t value_encrypted_base64_size = atchops_base64_encoded_size(value_encrypted_size) + 1;
  char value_encrypted_base64[value_encrypted_base64_size];

  char *update_cmd = NULL;
  char *metadata_protocol_str = NULL;
  char *atkey_str = NULL;

  const size_t recv_size = 256;
  unsigned char *recv = NULL;
  if (!ctx->async_read) {
    if ((recv = malloc(sizeof(unsigned char) * recv_size)) == NULL) {
      ret = 1;
      atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "Failed to allocate memory for recv\n");
      goto exit;
    }
    memset(recv, 0, sizeof(unsigned char) * recv_size);
  }
  size_t recv_len = 0;

  /*
   * 3. Get the shared_encrytion_key to use
   */
  if (!atclient_atkeys_is_self_encryption_key_base64_initialized(&(ctx->atkeys))) {
    ret = 1;
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "Self encryption key is not initialized\n");
    goto exit;
  }

  if ((ret = atchops_base64_decode((unsigned char *)ctx->atkeys.self_encryption_key_base64,
                                   strlen(ctx->atkeys.self_encryption_key_base64), self_encryption_key,
                                   self_encryption_key_size, NULL)) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atchops_base64_decode: %d\n", ret);
    goto exit;
  }

  /*
   * 4. Generate IV
   */
  if ((ret = atchops_iv_generate(iv)) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atchops_iv_generate: %d\n", ret);
    goto exit;
  }

  memset(iv_base64, 0, sizeof(unsigned char) * iv_base64_size);
  if ((ret = atchops_base64_encode(iv, iv_size, (unsigned char *) iv_base64, iv_base64_size, NULL)) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atchops_base64_encode: %d\n", ret);
    goto exit;
  }

  if ((ret = atclient_atkey_metadata_set_iv_nonce(&(atkey->metadata), iv_base64)) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atclient_atkey_metadata_set_iv_nonce: %d\n", ret);
    goto exit;
  }

  /*
   * 5. Encrypt value
   */
  size_t value_encrypted_len = 0;
  if ((ret = atchops_aes_ctr_encrypt(self_encryption_key, ATCHOPS_AES_256, iv, (unsigned char *)value, value_len,
                                     value_encrypted, value_encrypted_size, &value_encrypted_len)) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atchops_aes_ctr_encrypt: %d\n", ret);
    goto exit;
  }

  // log value_encrypted
  atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_DEBUG, "value_encrypted: ");
  for (size_t i = 0; i < value_encrypted_len; i++) {
    printf("%02x ", value_encrypted[i]);
  }
  printf("\n");

  // log value_encrypted_len
  atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_DEBUG, "value_encrypted_len: %zu\n", value_encrypted_len);
  atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_DEBUG, "value_encrypted_size: %zu\n", value_encrypted_size);

  size_t value_encrypted_base64_len = 0;
  memset(value_encrypted_base64, 0, sizeof(char) * value_encrypted_base64_size);
  if ((ret = atchops_base64_encode(value_encrypted, value_encrypted_len, (unsigned char *) value_encrypted_base64,
                                   value_encrypted_base64_size, &value_encrypted_base64_len)) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atchops_base64_encode: %d\n", ret);
    goto exit;
  }

  /*
   * 6. Build update command
   */

  // metadata protocol string
  if ((ret = atclient_atkey_metadata_to_protocol_str(&(atkey->metadata), &metadata_protocol_str)) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atclient_atkey_metadata_to_protocol_str: %d\n", ret);
    goto exit;
  }
  const size_t metadata_protocol_str_len = strlen(metadata_protocol_str);

  // atkey string
  if ((ret = atclient_atkey_to_string(atkey, &atkey_str)) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atclient_atkey_to_string: %d\n", ret);
    goto exit;
  }
  const size_t atkey_str_len = strlen(atkey_str);

  // update: command
  const size_t update_cmd_size = strlen("update") + metadata_protocol_str_len + strlen(":") + atkey_str_len +
                                 strlen(" ") + value_encrypted_base64_len + strlen("\r\n") + 1;
  if ((update_cmd = malloc(sizeof(char) * update_cmd_size)) == NULL) {
    ret = 1;
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "Failed to allocate memory for update_cmd\n");
    goto exit;
  }
  memset(update_cmd, 0, sizeof(char) * update_cmd_size);
  snprintf(update_cmd, update_cmd_size, "update%s:%s %s\r\n", metadata_protocol_str, atkey_str, value_encrypted_base64);
  const size_t update_cmd_len = update_cmd_size - 1;

  /*
   * 7. Send update command
   */
  if ((ret = atclient_connection_send(&ctx->atserver_connection, (unsigned char *)update_cmd, update_cmd_len, recv,
                                      recv_size, &recv_len)) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atclient_connection_send: %d\n", ret);
    goto exit;
  }

  if (ctx->async_read) {
    goto exit;
  }

  char *response = (char *)recv;

  if (!atclient_string_utils_starts_with(response, "data:")) {
    ret = 1;
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "recv was \"%.*s\" and did not have prefix \"data:\"\n",
                 (int)recv_len, recv);
    goto exit;
  }

  char *response_without_data = response + strlen("data:");

  /*
   * 5. Receive commit id
   */
  if (commit_id != NULL) {
    *commit_id = atoi(response_without_data);
  }

  ret = 0;
  goto exit;
exit: {
  free(recv);
  free(update_cmd);
  free(metadata_protocol_str);
  free(atkey_str);
  return ret;
}
}

static int atclient_put_self_key_validate_arguments(atclient *ctx, atclient_atkey *atkey, const char *value) {
  int ret = 1;

  if (ctx == NULL) {
    ret = 1;
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "ctx is NULL\n");
    goto exit;
  }

  if(!atclient_is_atserver_connection_started(&(ctx->atserver_connection))) {
    ret = 1;
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "ctx.atserver_connection is not started\n");
    goto exit;
  }

  if(!atclient_is_atsign_initialized(&(ctx->atserver_connection))) {
    ret = 1;
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "ctx.atserver_connection is not connected\n");
    goto exit;
  }

  if (atkey == NULL) {
    ret = 1;
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atkey is NULL\n");
    goto exit;
  }

  if(!atclient_atkey_is_key_initialized(atkey)) {
    ret = 1;
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atkey is not initialized\n");
    goto exit;
  }

  if(!atclient_atkey_is_shared_by_initialized(atkey)) {
    ret = 1;
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atkey.shared_by is not initialized\n");
    goto exit;
  }

  if (value == NULL) {
    ret = 1;
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "value is NULL\n");
    goto exit;
  }

  ret = 0;
  goto exit;
exit: { return ret; }
}