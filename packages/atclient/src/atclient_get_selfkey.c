#include "atclient/atclient.h"
#include "atclient/atkey.h"
#include "atclient/constants.h"
#include "atclient/stringutils.h"
#include <atchops/aes.h>
#include <atchops/aesctr.h>
#include <atchops/base64.h>
#include <atchops/iv.h>
#include <atchops/rsa.h>
#include <atlogger/atlogger.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>

#define TAG "atclient_get_selfkey"

static int atclient_get_selfkey_valid_arguments(const atclient *atclient, const atclient_atkey *atkey,
                                                const char *value, const size_t value_size, const size_t *value_len);

int atclient_get_selfkey(atclient *atclient, atclient_atkey *atkey, char *value, const size_t value_size,
                         size_t *value_len) {
  int ret = 1;

  /*
   * 1. Validate arguments
   */
  if ((ret = atclient_get_selfkey_valid_arguments(atclient, atkey, value, value_size, value_len)) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atclient_get_selfkey_valid_arguments: %d\n", ret);
    return ret;
  }

  /*
   * 2. Initialize variables
   */
  char *atkey_str = NULL;

  const size_t recv_size = value_size;
  unsigned char recv[recv_size];
  memset(recv, 0, sizeof(unsigned char) * recv_size);
  size_t recv_len = 0;

  const size_t self_encryption_size = ATCHOPS_AES_256 / 8; // 32 byte = 256 bits
  unsigned char self_encryption_key[self_encryption_size];
  memset(self_encryption_key, 0, sizeof(unsigned char) * self_encryption_size);
  size_t self_encryption_key_len = 0;

  unsigned char iv[ATCHOPS_IV_BUFFER_SIZE];

  // free later
  cJSON *root = NULL;
  char *llookup_cmd = NULL;
  char *value_raw = NULL;
  char *metadata_str = NULL;

  /*
   * 3. Build `llookup:` command
   */
  if ((ret = atclient_atkey_to_string(atkey, &atkey_str)) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atclient_atkey_to_string: %d\n", ret);
    goto exit;
  }

  const size_t atkey_strlen = strlen(atkey_str);

  const size_t llookup_cmd_size = strlen("llookup:all:\r\n") + atkey_strlen + 1;
  llookup_cmd = (char *)malloc(sizeof(char) * llookup_cmd_size);
  if (llookup_cmd == NULL) {
    ret = 1;
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "Failed to allocate memory for llookup_cmd\n");
    goto exit;
  }
  memset(llookup_cmd, 0, sizeof(char) * llookup_cmd_size);

  snprintf(llookup_cmd, llookup_cmd_size, "llookup:all:%.*s\r\n", (int)atkey_strlen, atkey_str);

  /*
   * 4. Send `llookup:` command
   */
  if ((ret = atclient_connection_send(&(atclient->atserver_connection), (unsigned char *)llookup_cmd,
                                      llookup_cmd_size - 1, recv, recv_size, &recv_len)) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atclient_connection_send: %d\n", ret);
    goto exit;
  }

  /*
   * 5. Parse response
   */
  char *response = (char *)recv;
  if (!atclient_stringutils_starts_with(response, "data:")) {
    ret = 1;
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "recv was \"%.*s\" and did not have prefix \"data:\"\n",
                 (int)recv_len, recv);
    goto exit;
  }

  char *response_without_data = (char *)recv + 5;

  if ((root = cJSON_Parse(response_without_data)) == NULL) {
    ret = 1;
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "cJSON_Parse: %d\n", ret);
    goto exit;
  }

  cJSON *metadata = cJSON_GetObjectItem(root, "metaData");
  if (metadata == NULL) {
    ret = 1;
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "cJSON_GetObjectItem: %d\n", ret);
    goto exit;
  }

  metadata_str = cJSON_Print(metadata);

  if ((ret = atclient_atkey_metadata_from_json_str(&(atkey->metadata), metadata_str)) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atclient_atkey_metadata_from_json_str: %d\n", ret);
    goto exit;
  }

  /**
   * 6. Decrypt value
   */
  if (atclient_atkey_metadata_is_iv_nonce_initialized(&atkey->metadata)) {
    if ((ret = atchops_base64_decode((unsigned char *)atkey->metadata.iv_nonce, strlen(atkey->metadata.iv_nonce), iv,
                                     ATCHOPS_IV_BUFFER_SIZE, NULL)) != 0) {
      atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atchops_base64_decode: %d\n", ret);
      goto exit;
    }
  } else {
    // use legacy IV
    memset(iv, 0, sizeof(unsigned char) * ATCHOPS_IV_BUFFER_SIZE);
  }

  cJSON *data = cJSON_GetObjectItem(root, "data");
  if (data == NULL) {
    ret = 1;
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "cJSON_GetObjectItem: %d\n", ret);
    goto exit;
  }

  if ((ret = atchops_base64_decode((unsigned char *)atclient->atkeys.self_encryption_key_base64,
                                   strlen(atclient->atkeys.self_encryption_key_base64), self_encryption_key,
                                   self_encryption_size, &self_encryption_key_len)) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atchops_base64_decode: %d\n", ret);
    goto exit;
  }

  // holds base64 decoded value. Once decoded, it is encrypted cipher text bytes that need to be decrypted
  const size_t value_raw_size = atchops_base64_decoded_size(strlen(data->valuestring));
  if ((value_raw = (char *)malloc(sizeof(char) * value_raw_size)) == NULL) {
    ret = 1;
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "Failed to allocate memory for value_raw\n");
    goto exit;
  }
  memset(value_raw, 0, sizeof(char) * value_raw_size);
  size_t value_raw_len = 0;

  if ((ret = atchops_base64_decode((unsigned char *)data->valuestring, strlen(data->valuestring),
                                   (unsigned char *)value_raw, value_raw_size, &value_raw_len)) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atchops_base64_decode: %d\n", ret);
    goto exit;
  }

  if ((ret = atchops_aesctr_decrypt(self_encryption_key, ATCHOPS_AES_256, iv, (unsigned char *)value_raw, value_raw_len,
                                    (unsigned char *)value, value_size, value_len)) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atchops_aesctr_decrypt: %d\n", ret);
    goto exit;
  }

  ret = 0;
  goto exit;

exit: {
  if (root != NULL) {
    cJSON_Delete(root);
  }
  free(value_raw);
  free(llookup_cmd);
  free(atkey_str);
  free(metadata_str);
  return ret;
}
}

static int atclient_get_selfkey_valid_arguments(const atclient *atclient, const atclient_atkey *atkey,
                                                const char *value, const size_t value_size, const size_t *value_len) {
  int ret = 1;

  if (atclient == NULL) {
    ret = 1;
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atclient is NULL\n");
    goto exit;
  }

  if (!atclient_is_atsign_initialized(atclient)) {
    ret = 1;
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atclient_is_atsign_initialized is false\n");
    goto exit;
  }

  if (!atclient_is_atserver_connection_started(atclient)) {
    ret = 1;
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atclient_is_atserver_connection_started is false\n");
    goto exit;
  }

  if (atclient->async_read) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR,
                 "atclient_get_selfkey cannot be called from an async_read atclient, it will cause a race condition\n");
    return 1;
  }

  if (atkey == NULL) {
    ret = 1;
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atkey is NULL\n");
    goto exit;
  }

  if (!atclient_atkey_is_key_initialized(atkey)) {
    ret = 1;
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atkey.key is not initialized when it should be\n");
    goto exit;
  }

  if (!atclient_atkey_is_shared_by_initialized(atkey)) {
    ret = 1;
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atkey.shared_by is not initialized when it should be\n");
    goto exit;
  }

  if (value == NULL) {
    ret = 1;
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "value is NULL\n");
    goto exit;
  }

  if (value_size == 0) {
    ret = 1;
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "value_size is 0\n");
    goto exit;
  }

  if (value_len == NULL) {
    ret = 1;
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "value_len is NULL\n");
    goto exit;
  }

  ret = 0;
exit: { return ret; }
}