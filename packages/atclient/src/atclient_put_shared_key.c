#include <atchops/aes_ctr.h>
#include <atchops/base64.h>
#include <atclient/atclient.h>
#include <atclient/atkey.h>
#include <atclient/constants.h>
#include <atclient/encryption_key_helpers.h>
#include <atclient/request_options.h>
#include <atclient/string_utils.h>
#include <atlogger/atlogger.h>
#include <stdlib.h>
#include <string.h>

#define TAG "atclient_put_self_key"

static int atclient_put_shared_key_validate_arguments(const atclient *ctx, const atclient_atkey *atkey,
                                                      const char *value,
                                                      const atclient_put_shared_key_request_options *request_options,
                                                      const int *commit_id);

int atclient_put_shared_key(atclient *ctx, atclient_atkey *atkey, const char *value,
                            const atclient_put_shared_key_request_options *request_options, int *commit_id) {
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
  char *recipient_atsign_with_at = NULL;

  const size_t shared_encryption_key_size = ATCHOPS_AES_256 / 8;
  unsigned char shared_encryption_key[shared_encryption_key_size];

  const size_t value_encrypted_size = atchops_aes_ctr_ciphertext_size(strlen(value));
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
   * 3. Get shared_encryption_key to use
   */
  if ((ret = atclient_string_utils_atsign_with_at(atkey->shared_with, &recipient_atsign_with_at)) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atclient_string_utils_atsign_with_at: %d\n", ret);
    goto exit;
  }

  if (request_options != NULL &&
      atclient_put_shared_key_request_options_is_shared_encryption_key_initialized(request_options)) {
    memcpy(shared_encryption_key, request_options->shared_encryption_key, shared_encryption_key_size);
  } else if ((ret = atclient_get_shared_encryption_key_shared_by_me(ctx, recipient_atsign_with_at,
                                                                    shared_encryption_key)) != 0) {
    if (ret != ATCLIENT_ERR_AT0015_KEY_NOT_FOUND) {
      atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atclient_get_shared_encryption_key_shared_by_me: %d\n", ret);
      goto exit;
    }
    if ((ret = atclient_create_shared_encryption_key_pair_for_me_and_other(ctx, recipient_atsign_with_at,
                                                                           shared_encryption_key)) != 0) {
      atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR,
                   "atclient_create_shared_encryption_key_pair_for_me_and_other: %d\n", ret);
      goto exit;
    }
  } else {
    ret = 1;
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "could not find shared encryption key\n");
    goto exit;
  }

  /*
   * 4. Encrypt value
   */
  size_t value_encrypted_len = 0;
  memset(value_encrypted, 0, sizeof(unsigned char) * value_encrypted_size);
  if ((ret = atchops_aes_ctr_encrypt(shared_encryption_key, ATCHOPS_AES_256, iv, value, strlen(value), value_encrypted,
                                     value_encrypted_size, &value_encrypted_len)) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atchops_aes_ctr_encrypt: %d\n", ret);
    goto exit;
  }

  size_t value_encrypted_base64_len = 0;
  memset(value_encrypted_base64, 0, sizeof(char) * value_encrypted_base64_size);
  if((ret = atchops_base64_encode(value_encrypted, value_encrypted_len, value_encrypted_base64, value_encrypted_base64_size, &value_encrypted_base64_len)) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atchops_base64_encode: %d\n", ret);
    goto exit;
  }

  /*
   * 5. Create update command
   */
  if ((ret = atclient_atkey_metadata_to_protocol_str(atkey, &metadata_protocol_str)) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atclient_atkey_metadata_to_protocol_str: %d\n", ret);
    goto exit;
  }
  const size_t metadata_protocol_str_len = strlen(metadata_protocol_str);

  if ((ret = atclient_atkey_to_string(atkey, &atkey_str)) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atclient_atkey_to_string: %d\n", ret);
    goto exit;
  }
  const size_t atkey_str_len = strlen(atkey_str);

  const size_t update_cmd_size =
      strlen("update:") + atkey_str_len + metadata_protocol_str_len + strlen(": ") + value_encrypted_base64_len + strlen("\r\n") + 1;
  if ((update_cmd = malloc(sizeof(char) * update_cmd_size)) == NULL) {
    ret = 1;
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "Failed to allocate memory for update_cmd\n");
    goto exit;
  }

  snprintf(update_cmd, update_cmd_size, "update:%s%s: %s\r\n", atkey_str, metadata_protocol_str, value);
  const size_t update_cmd_len = update_cmd_size - 1;

  /*
   * 6. Send update command
   */
  if ((ret = atclient_connection_send(&ctx->atserver_connection, update_cmd, update_cmd_len, recv, recv_size,
                                      &recv_len)) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atclient_connection_send: %d\n", ret);
    goto exit;
  }

  if (ctx->async_read) {
    goto exit;
  }

  char *response = (char *)recv;

  /*
   * 7. Return commit id
   */
  if (commit_id != NULL) {
    if (!atclient_string_utils_starts_with(response, "data:")) {
      ret = 1;
      atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "recv was \"%.*s\" and did not have prefix \"data:\"\n",
                   (int)recv_len, recv);
      goto exit;
    }

    char *response_without_data = response + strlen("data:");

    *commit_id = atoi(response_without_data);
  }

  ret = 0;
  goto exit;
exit: { return ret; }
}

static int atclient_put_shared_key_validate_arguments(const atclient *ctx, const atclient_atkey *atkey,
                                                      const char *value,
                                                      const atclient_put_shared_key_request_options *request_options,
                                                      const int *commit_id) {
  int ret = 1;

  char *shared_by_formatted = NULL;
  char *ctx_atsign_formatted = NULL;

  if (ctx == NULL) {
    ret = 1;
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "ctx is NULL\n");
    goto exit;
  }

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

  if (request_options == NULL) {
    ret = 1;
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "request_options is NULL\n");
    goto exit;
  }

  if (commit_id == NULL) {
    ret = 1;
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "commit_id is NULL\n");
    goto exit;
  }

  const atkey_type = atclient_atkey_get_type(atkey);

  if (atkey_type != ATKEY_TYPE_SHAREDKEY) {
    ret = 1;
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atkey_type is not ATKEY_TYPE_SHAREDKEY\n");
    goto exit;
  }

  if (!atclient_atkey_is_key_initialized(atkey)) {
    ret = 1;
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atclient_atkey_is_key_initialized is false\n");
    goto exit;
  }

  if (!atclient_atkey_is_shared_by_initialized(atkey)) {
    ret = 1;
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atclient_atkey_is_shared_by_initialized is false\n");
    goto exit;
  }

  if (!atclient_atkey_is_shared_with_initialized(atkey)) {
    ret = 1;
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atclient_atkey is_shared_with_initialized is false\n");
    goto exit;
  }

  if ((ret = atclient_string_utils_atsign_with_at(ctx->atsign, &ctx_atsign_formatted)) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atclient_string_utils_atsign_with_at: %d\n", ret);
    goto exit;
  }

  if ((ret = atclient_string_utils_atsign_with_at(atkey->shared_by, &shared_by_formatted)) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atclient_string_utils_atsign_with_at: %d\n", ret);
    goto exit;
  }

  if (strcmp(ctx_atsign_formatted, shared_by_formatted) != 0) {
    ret = 1;
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atkey->shared_by is not equal to ctx->atsign\n");
    goto exit;
  }

  ret = 0;
  goto exit;
exit: {
  free(shared_by_formatted);
  free(ctx_atsign_formatted);
  return ret;
}
}