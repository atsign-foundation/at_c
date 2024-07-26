#include <atchops/aes_ctr.h>
#include <atchops/base64.h>
#include <atchops/iv.h>
#include <atclient/atclient.h>
#include <atclient/string_utils.h>
#include <atclient/atkey.h>
#include <atclient/request_options.h>
#include <atlogger/atlogger.h>
#include <stdlib.h>
#include <string.h>

#define TAG "atclient_put_self_key"

static int atclient_put_self_key_validate_arguments(atclient *ctx, atclient_atkey *atkey, const char *value,
                                                    const atclient_put_self_key_request_options *request_options,
                                                    int *commit_id);

int atclient_put_self_key(atclient *ctx, atclient_atkey *atkey, const char *value,
                          const atclient_put_self_key_request_options *request_options, int *commit_id) {
  int ret = 1;

  /*
   * 1. Validate arguments
   */
  if ((ret = atclient_put_self_key_validate_arguments(ctx, atkey, value, request_options, commit_id)) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atclient_put_self_key_validate_arguments: %d\n", ret);
    return ret;
  }

  /*
   * 2. Variables
   */
  const size_t shared_encryption_key_size = ATCHOPS_AES_256 / 8;
  unsigned char shared_encryption_key[shared_encryption_key_size];

  const size_t iv_size = ATCHOPS_IV_BUFFER_SIZE;
  unsigned char iv[iv_size];

  const size_t iv_base64_size = atchops_base64_encoded_size(iv_size);
  char iv_base64[iv_base64_size];

  const size_t value_len = strlen(value);

  const size_t value_encrypted_size = atchops_aes_ctr_ciphertext_size(value_len);
  unsigned char value_encrypted[value_encrypted_size];

  const size_t value_encrypted_base64_size = atchops_base64_encoded_size(value_encrypted_size);
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
                                   strlen(ctx->atkeys.self_encryption_key_base64), shared_encryption_key,
                                   shared_encryption_key_size, NULL)) != 0) {
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

  memset(iv_base64, 0, sizeof(unsigned char) * ATCHOPS_IV_BUFFER_SIZE);
  if ((ret = atchops_base64_encode(iv, iv_size, iv_base64, iv_base64_size, NULL)) != 0) {
  }

  if ((ret = atclient_atkey_metadata_set_iv_nonce(atkey, iv_base64)) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atclient_atkey_metadata_set_iv_nonce: %d\n", ret);
    goto exit;
  }

  /*
   * 5. Encrypt value
   */
  size_t value_encrypted_len = 0;
  memset(value_encrypted, 0, sizeof(unsigned char) * value_encrypted_size);
  if ((ret = atchops_aes_ctr_encrypt(shared_encryption_key, ATCHOPS_AES_256, iv, (unsigned char *)value, value_len,
                                     value_encrypted, value_encrypted_size, &value_encrypted_len)) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atchops_aes_ctr_encrypt: %d\n", ret);
    goto exit;
  }

  size_t value_encrypted_base64_len = 0;
  memset(value_encrypted_base64, 0, sizeof(char) * value_encrypted_base64_size);
  if ((ret = atchops_base64_encode(value_encrypted, value_encrypted_len, value_encrypted_base64,
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
  const size_t update_cmd_size =
      strlen("update") + metadata_protocol_str_len + strlen(":") + atkey_str_len + strlen(" ") + value_len + strlen("\r\n") + 1;
  if ((update_cmd = malloc(sizeof(char) * update_cmd_size)) == NULL) {
    ret = 1;
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "Failed to allocate memory for update_cmd\n");
    goto exit;
  }
  memset(update_cmd, 0, sizeof(char) * update_cmd_size);
  snprintf(update_cmd, update_cmd_size, "update%s:%s %s\r\n", atkey_str, metadata_protocol_str, value);
  const size_t update_cmd_len = update_cmd_size - 1;

  /*
   * 7. Send update command
   */
  if ((ret = atclient_connection_send(&ctx->atserver_connection, (unsigned char *) update_cmd, update_cmd_len, recv, recv_size,
                                      &recv_len)) != 0) {
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
exit: { return ret; }
}

static int atclient_put_self_key_validate_arguments(atclient *ctx, atclient_atkey *atkey, const char *value,
                                                    const atclient_put_self_key_request_options *request_options,
                                                    int *commit_id) {
  int ret = 1;

  if (ctx == NULL) {
    ret = 1;
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "ctx is NULL\n");
    goto exit;
  }

  // TODO atclient checks

  if (atkey == NULL) {
    ret = 1;
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atkey is NULL\n");
    goto exit;
  }

  if (value == NULL) {
    ret = 1;
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "value is NULL\n");
    goto exit;
  }

  // TODO more checks

  ret = 0;
  goto exit;
exit: { return ret; }
}