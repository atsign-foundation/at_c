#include "atclient/atclient.h"
#include "atclient/encryption_key_helpers.h"
#include "atclient/string_utils.h"
#include <atchops/aes.h>
#include <atchops/aes_ctr.h>
#include <atchops/base64.h>
#include <atchops/iv.h>
#include <atlogger/atlogger.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <atclient/constants.h>

#define TAG "atclient_get_sharedkey"

static int atclient_get_shared_key_validate_arguments(const atclient *atclient, const atclient_atkey *atkey,
                                                      const char **value,
                                                      const atclient_get_shared_key_request_options *request_options);

static int
atclient_get_shared_key_shared_by_me_with_other(atclient *atclient, atclient_atkey *atkey, char **value,
                                                const atclient_get_shared_key_request_options *request_options);

static int
atclient_get_shared_key_shared_by_other_with_me(atclient *atclient, atclient_atkey *atkey, char **value,
                                                const atclient_get_shared_key_request_options *request_options);

int atclient_get_shared_key(atclient *atclient, atclient_atkey *atkey,
                            char **value, const atclient_get_shared_key_request_options *request_options) {
  int ret = 1;

  if ((ret = atclient_get_shared_key_validate_arguments(atclient, atkey, (const char **) value, request_options)) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atclient_get_shared_key_validate_arguments: %d\n", ret);
    return ret;
  }

  char *client_atsign_with_at = NULL;
  char *sharedby_atsign_with_at = NULL;

  if ((ret = atclient_string_utils_atsign_with_at(atclient->atsign, &client_atsign_with_at)) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atclient_string_utils_atsign_with_at: %d\n", ret);
    goto exit;
  }

  if ((ret = atclient_string_utils_atsign_with_at(atkey->shared_by, &sharedby_atsign_with_at)) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atclient_string_utils_atsign_with_at: %d\n", ret);
    goto exit;
  }

  if (strcmp(sharedby_atsign_with_at, client_atsign_with_at) != 0) {
    if ((ret = atclient_get_shared_key_shared_by_other_with_me(atclient, atkey, value, request_options)) != 0) {
      atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atclient_get_shared_key_shared_by_other_with_me: %d\n", ret);
      goto exit;
    }
  } else {
    if ((ret = atclient_get_shared_key_shared_by_me_with_other(atclient, atkey, value, request_options)) != 0) {
      atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atclient_get_shared_key_shared_by_me_with_other: %d\n", ret);
      goto exit;
    }
  }

  goto exit;
exit: {
  free(client_atsign_with_at);
  free(sharedby_atsign_with_at);
  return ret;
}
}

static int atclient_get_shared_key_validate_arguments(const atclient *atclient, const atclient_atkey *atkey,
                                                      const char **value,
                                                      const atclient_get_shared_key_request_options *request_options) {
  int ret = 1;

  if (atclient == NULL) {
    ret = 1;
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atclient is NULL\n");
    goto exit;
  }

  if (!atclient_is_atserver_connection_started(atclient)) {
    ret = 1;
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atserver connection was not started\n");
    goto exit;
  }

  if (!atclient_is_atsign_initialized(atclient)) {
    ret = 1;
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atclient_is_atsign_initialized was not set\n");
    goto exit;
  }

  if (atclient->async_read) {
    ret = 1;
    atlogger_log(
        TAG, ATLOGGER_LOGGING_LEVEL_ERROR,
        "atclient_get_shared_key cannot be called from an async_read atclient, it will cause a race condition\n");
    goto exit;
  }

  if (atkey == NULL) {
    ret = 1;
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atkey is NULL\n");
    goto exit;
  }

  if (atclient_atkey_get_type(atkey) != ATCLIENT_ATKEY_TYPE_SHARED_KEY) {
    ret = 1;
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atkey is not a shared key\n");
    goto exit;
  }

  if (!atclient_atkey_is_key_initialized(atkey) || strlen(atkey->key) <= 0) {
    ret = 1;
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "key is not initialized or is empty\n");
    goto exit;
  }

  if (!atclient_atkey_is_shared_by_initialized(atkey) || strlen(atkey->key) <= 0) {
    ret = 1;
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "shared_by is not initialized or is empty\n");
    goto exit;
  }

  if (!atclient_atkey_is_shared_with_initialized(atkey) || strlen(atkey->key) <= 0) {
    ret = 1;
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "shared_with is not initialized or is empty\n");
    goto exit;
  }

  ret = 0;
exit: { return ret; }
}

static int atclient_get_shared_key_shared_by_me_with_other(
    atclient *atclient, atclient_atkey *atkey,
    char **value, const atclient_get_shared_key_request_options *request_options) {
  int ret = 1;

  /*
   * 1. Validate arguments
   */
  // TODO

  /*
   * 2. Variables
   */
  char *client_atsign_with_at = NULL;
  char *recipient_atsign_with_at = NULL;

  const size_t shared_encryption_key_to_use_size = ATCHOPS_AES_256 / 8;
  unsigned char shared_encryption_key_to_use[shared_encryption_key_to_use_size];
  memset(shared_encryption_key_to_use, 0, sizeof(unsigned char) * shared_encryption_key_to_use_size);

  char *atkey_str = NULL;
  char *llookup_cmd = NULL;

  const size_t recv_size = 4096;
  unsigned char recv[recv_size];
  size_t recv_len = 0;

  const size_t iv_size = ATCHOPS_IV_BUFFER_SIZE;
  unsigned char iv[iv_size];

  unsigned char *value_raw_encrypted = NULL;
  unsigned char *value_raw = NULL;

  cJSON *root = NULL;

  char *metadata_str = NULL;

  atclient_atkey_metadata metadata;
  atclient_atkey_metadata_init(&metadata);

  /*
   * 3. Format atSigns
   */
  if ((ret = atclient_string_utils_atsign_with_at(atclient->atsign, &client_atsign_with_at)) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atclient_string_utils_atsign_with_at: %d\n", ret);
    goto exit;
  }

  if ((ret = atclient_string_utils_atsign_with_at(atkey->shared_with, &recipient_atsign_with_at)) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atclient_string_utils_atsign_with_at: %d\n", ret);
    goto exit;
  }

  /*
   * 4. Get shared_encryption_key, if necessary
   */
  if (request_options != NULL &&
      atclient_get_shared_key_request_options_is_shared_encryption_key_initialized(request_options)) {
    memcpy(shared_encryption_key_to_use, request_options->shared_encryption_key, shared_encryption_key_to_use_size);
  } else {
    if ((ret = atclient_get_shared_encryption_key_shared_by_me(atclient, atkey->shared_with,
                                                               shared_encryption_key_to_use)) != 0) {
      atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atclient_get_shared_encryption_key_shared_by_me: %d\n", ret);
      goto exit;
    }
  }

  /*
   * 5. Build `llookup:all:` llookup_cmd
   */
  if ((ret = atclient_atkey_to_string(atkey, &atkey_str)) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atclient_atkey_to_string: %d\n", ret);
    goto exit;
  }
  const size_t atkey_strlen = strlen(atkey_str);

  const size_t llookup_cmd_size = strlen("llookup:all:") + atkey_strlen + strlen("\r\n") + 1;
  if ((llookup_cmd = malloc(sizeof(char) * llookup_cmd_size)) == NULL) {
    ret = 1;
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "Failed to allocate memory for llookup_cmd\n");
    goto exit;
  }
  snprintf(llookup_cmd, llookup_cmd_size, "llookup:all:%s\r\n", atkey_str);

  /*
   * 6. Send llookup:all: llookup_cmd
   */
  if ((ret = atclient_connection_send(&(atclient->atserver_connection), (unsigned char *)llookup_cmd,
                                      llookup_cmd_size - 1, recv, recv_size, &recv_len)) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atclient_connection_send: %d\n", ret);
    goto exit;
  }

  /*
   * 7. Parse response
   */
  char *response = (char *)recv;
  char *response_trimmed = NULL;
  // below method points the response_trimmed variable to the position of 'data:' substring
  if(atclient_string_utils_get_substring_position(response, DATA_TOKEN, &response_trimmed) != 0) {
    ret = 1;
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "recv was \"%.*s\" and did not have prefix \"data:\"\n",
                 (int)recv_len, recv);
    goto exit;
  }
  response_trimmed = response_trimmed + 5; // +5 to skip the "data:" prefix

  if ((root = cJSON_Parse(response_trimmed)) == NULL) {
    ret = 1;
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "cJSON_Parse: %d\n", ret);
    goto exit;
  }

  cJSON *metadata_json = cJSON_GetObjectItem(root, "metaData");
  if (metadata_json == NULL) {
    ret = 1;
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "cJSON_GetObjectItem: %d\n", ret);
    goto exit;
  }

  if ((metadata_str = cJSON_Print(metadata_json)) == NULL) {
    ret = 1;
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "cJSON_Print: %d\n", ret);
    goto exit;
  }

  if ((ret = atclient_atkey_metadata_from_json_str(&metadata, metadata_str)) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atclient_atkey_metadata_from_json_str: %d\n", ret);
    goto exit;
  }

  cJSON *data = cJSON_GetObjectItem(root, "data");
  if (data == NULL) {
    ret = 1;
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "cJSON_GetObjectItem: %d\n", ret);
    goto exit;
  }

  /*
   * 8. Set IV in the AtKey
   */
  if (atclient_atkey_metadata_is_iv_nonce_initialized(&metadata)) {
    if ((ret = atchops_base64_decode((unsigned char *)metadata.iv_nonce, strlen(metadata.iv_nonce), iv, iv_size,
                                     NULL)) != 0) {
      atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atchops_base64_decode: %d\n", ret);
      goto exit;
    }
  } else {
    memset(iv, 0, sizeof(unsigned char) * iv_size);
  }

  /*
   * 9. Decrypt data
   */
  const char *value_raw_encrypted_base64 = data->valuestring;
  const size_t value_raw_encrypted_base64_len = strlen(data->valuestring);

  const size_t value_raw_encrypted_size = atchops_base64_decoded_size(value_raw_encrypted_base64_len);
  if ((value_raw_encrypted = malloc(sizeof(unsigned char) * value_raw_encrypted_size)) == NULL) {
    ret = 1;
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "Failed to allocate memory for value_raw_encrypted\n");
    goto exit;
  }
  memset(value_raw_encrypted, 0, sizeof(unsigned char) * value_raw_encrypted_size);
  size_t value_raw_encrypted_len = 0;
  if ((ret = atchops_base64_decode((unsigned char *)value_raw_encrypted_base64, value_raw_encrypted_base64_len,
                                   value_raw_encrypted, value_raw_encrypted_size, &value_raw_encrypted_len)) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atchops_base64_decode: %d\n", ret);
    goto exit;
  }

  const size_t value_raw_size = atchops_aes_ctr_plaintext_size(value_raw_encrypted_len);
  if ((value_raw = malloc(sizeof(unsigned char) * value_raw_size)) == NULL) {
    ret = 1;
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "Failed to allocate memory for value_raw\n");
    goto exit;
  }
  memset(value_raw, 0, sizeof(unsigned char) * value_raw_size);
  size_t value_raw_len = 0;

  if ((ret = atchops_aes_ctr_decrypt(shared_encryption_key_to_use, ATCHOPS_AES_256, iv, value_raw_encrypted,
                                     value_raw_encrypted_len, value_raw, value_raw_size, &value_raw_len)) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atchops_aes_ctr_decrypt: %d\n", ret);
    goto exit;
  }

  /*
   * 10. Set value
   */

  if (request_options != NULL &&
      atclient_get_shared_key_request_options_is_store_atkey_metadata_initialized(request_options) &&
      request_options->store_atkey_metadata) {
    if ((ret = atclient_atkey_metadata_from_json_str(&atkey->metadata, metadata_str)) != 0) {
      atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atclient_atkey_metadata_copy: %d\n", ret);
      goto exit;
    }
  }

  if (value != NULL) {
    if ((*value = malloc(sizeof(char) * (value_raw_len + 1))) == NULL) {
      ret = 1;
      atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "Failed to allocate memory for value\n");
      goto exit;
    }
    memcpy(*value, value_raw, value_raw_len);
    (*value)[value_raw_len] = '\0';
  }

  ret = 0;
  goto exit;
exit: {
  free(client_atsign_with_at);
  free(recipient_atsign_with_at);
  free(value_raw);
  free(atkey_str);
  free(llookup_cmd);
  free(metadata_str);
  cJSON_Delete(root);
  atclient_atkey_metadata_free(&metadata);
  return ret;
}
}

static int
atclient_get_shared_key_shared_by_other_with_me(atclient *atclient, atclient_atkey *atkey, char **value,
                                                const atclient_get_shared_key_request_options *request_options) {
  int ret = 1;

  /*
   * 1. Validate arguments
   */
  // TODO

  /*
   * 2. Variables
   */
  char *sender_atsign_with_at = NULL;
  char *recipient_atsign_with_at = NULL;

  const size_t shared_encryption_key_size = ATCHOPS_AES_256 / 8;
  unsigned char shared_encryption_key_to_use[shared_encryption_key_size];

  const size_t recv_size = 8192; // TODO use atclient_connection_read to realloc stuff
  unsigned char recv[recv_size];

  char *llookup_cmd = NULL;

  cJSON *root = NULL;
  char *metadata_str = NULL;

  atclient_atkey_metadata metadata;
  atclient_atkey_metadata_init(&metadata);

  const size_t iv_size = ATCHOPS_IV_BUFFER_SIZE;
  unsigned char iv[iv_size];

  unsigned char *value_raw_encryted = NULL;
  unsigned char *value_raw = NULL;

  /*
   * 3. Format atSigns
   */
  if ((ret = atclient_string_utils_atsign_with_at(atkey->shared_by, &sender_atsign_with_at)) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atclient_string_utils_atsign_with_at: %d\n", ret);
    goto exit;
  }

  if ((ret = atclient_string_utils_atsign_with_at(atkey->shared_with, &recipient_atsign_with_at)) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atclient_string_utils_atsign_with_at: %d\n", ret);
    goto exit;
  }

  /*
   * 4. Get shared_encryption_key, if necessary
   */
  if (request_options != NULL &&
      atclient_get_shared_key_request_options_is_shared_encryption_key_initialized(request_options)) {
    memcpy(shared_encryption_key_to_use, request_options->shared_encryption_key, shared_encryption_key_size);
  } else {
    if ((ret = atclient_get_shared_encryption_key_shared_by_other(atclient, atkey->shared_by,
                                                                  shared_encryption_key_to_use)) != 0) {
      atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atclient_get_shared_encryption_key_shared_by_other: %d\n", ret);
      goto exit;
    }
  }

  /*
   * 5. Build lookup: llookup_cmd
   */
  size_t llookup_cmd_size = strlen("lookup:all:") + strlen(atkey->key);
  bool namespace_exists = atclient_atkey_is_namespacestr_initialized(atkey);
  if (namespace_exists) {
    llookup_cmd_size += strlen(".") + strlen(atkey->namespace_str);
  }
  llookup_cmd_size += strlen(sender_atsign_with_at) + strlen("\r\n") + 1;
  if ((llookup_cmd = (char *)malloc(sizeof(char) * llookup_cmd_size)) == NULL) {
    ret = 1;
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "Failed to allocate memory for llookup_cmd\n");
    goto exit;
  }
  if (namespace_exists) {
    snprintf(llookup_cmd, llookup_cmd_size, "lookup:all:%s.%s%s\r\n", atkey->key, atkey->namespace_str,
             sender_atsign_with_at);
  } else {
    snprintf(llookup_cmd, llookup_cmd_size, "lookup:all:%s%s\r\n", atkey->key, sender_atsign_with_at);
  }

  /*
   * 6. Send lookup: llookup_cmd
   */
  memset(recv, 0, sizeof(unsigned char) * recv_size);
  size_t recv_len = 0;
  if ((ret = atclient_connection_send(&(atclient->atserver_connection), (unsigned char *)llookup_cmd,
                                      llookup_cmd_size - 1, recv, recv_size, &recv_len)) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atclient_connection_send: %d\n", ret);
    goto exit;
  }

  /*
   * 7. Parse response
   */
  char *response = (char *)recv;
  char *response_trimmed = NULL;
  // below method points the response_trimmed variable to the position of 'data:' substring
  if(atclient_string_utils_get_substring_position(response, DATA_TOKEN, &response_trimmed) != 0) {
    ret = 1;
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "recv was \"%.*s\" and did not have prefix \"data:\"\n",
                 (int)recv_len, recv);
    goto exit;
  }
  response_trimmed = response_trimmed + 5; // +5 to skip the "data:" prefix

  if ((root = cJSON_Parse(response_trimmed)) == NULL) {
    ret = 1;
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "cJSON_Parse: %d\n", ret);
    goto exit;
  }

  cJSON *metadata_json = cJSON_GetObjectItem(root, "metaData");
  if (metadata_json == NULL) {
    ret = 1;
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "cJSON_GetObjectItem: %d\n", ret);
    goto exit;
  }

  metadata_str = cJSON_Print(metadata_json);

  if ((ret = atclient_atkey_metadata_from_json_str(&metadata, metadata_str)) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atclient_atkey_metadata_from_json_str: %d\n", ret);
    goto exit;
  }

  cJSON *data = cJSON_GetObjectItem(root, "data");
  if (data == NULL) {
    ret = 1;
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "cJSON_GetObjectItem: %d\n", ret);
    goto exit;
  }

  /*
   * 8. Set IV
   */
  if (atclient_atkey_metadata_is_iv_nonce_initialized(&metadata)) {
    if ((ret = atchops_base64_decode((unsigned char *)metadata.iv_nonce, strlen(metadata.iv_nonce), iv, iv_size,
                                     NULL)) != 0) {
      atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atchops_base64_decode: %d\n", ret);
      goto exit;
    }
  } else {
    memset(iv, 0, sizeof(unsigned char) * iv_size);
  }

  /*
   * 9. Decrypt data
   */
  const unsigned char *value_raw_encrypted_base64 = (unsigned char *)data->valuestring;
  const size_t value_raw_encrypted_base64_len = strlen(data->valuestring);

  // 9a. base64 decode
  const size_t value_raw_encryted_size = atchops_base64_decoded_size(value_raw_encrypted_base64_len);
  if ((value_raw_encryted = malloc(sizeof(unsigned char) * value_raw_encryted_size)) == NULL) {
    ret = 1;
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "Failed to allocate memory for value_raw_encryted\n");
    goto exit;
  }
  memset(value_raw_encryted, 0, sizeof(unsigned char) * value_raw_encryted_size);
  size_t value_raw_encryted_len = 0;
  if ((ret = atchops_base64_decode(value_raw_encrypted_base64, value_raw_encrypted_base64_len, value_raw_encryted,
                                   value_raw_encryted_size, &value_raw_encryted_len)) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atchops_base64_decode: %d\n", ret);
    goto exit;
  }

  // 9b. aes decrypt
  const size_t value_raw_size = atchops_aes_ctr_plaintext_size(value_raw_encryted_len);
  if ((value_raw = malloc(sizeof(unsigned char) * value_raw_size)) == NULL) {
    ret = 1;
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "Failed to allocate memory for value_raw\n");
    goto exit;
  }
  memset(value_raw, 0, sizeof(unsigned char) * value_raw_size);
  size_t value_raw_len = 0;
  if ((ret = atchops_aes_ctr_decrypt(shared_encryption_key_to_use, ATCHOPS_AES_256, iv, value_raw_encryted,
                                     value_raw_encryted_len, (unsigned char *)value_raw, value_raw_size,
                                     &value_raw_len)) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atchops_aes_ctr_decrypt: %d\n", ret);
    goto exit;
  }

  /*
   * 10. Set value
   */
  if (request_options != NULL &&
      atclient_get_shared_key_request_options_is_store_atkey_metadata_initialized(request_options) &&
      request_options->store_atkey_metadata) {
    if ((ret = atclient_atkey_metadata_from_json_str(&(atkey->metadata), metadata_str)) != 0) {
      atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atclient_atkey_metadata_from_json_str: %d\n", ret);
      goto exit;
    }
  }

  if (value != NULL) {
    if ((*value = malloc(sizeof(char) * (value_raw_len + 1))) == NULL) {
      ret = 1;
      atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "Failed to allocate memory for value\n");
      goto exit;
    }
    memcpy(*value, value_raw, value_raw_len);
    (*value)[value_raw_len] = '\0';
  }

  ret = 0;
  goto exit;
exit: {
  free(sender_atsign_with_at);
  free(recipient_atsign_with_at);
  free(value_raw_encryted);
  free(value_raw);
  free(llookup_cmd);
  free(metadata_str);
  cJSON_Delete(root);
  atclient_atkey_metadata_free(&metadata);
  return ret;
}
}
