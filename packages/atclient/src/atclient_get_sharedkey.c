#include "atclient/atclient.h"
#include "atclient/encryption_key_helpers.h"
#include "atclient/stringutils.h"
#include <atchops/aes.h>
#include <atchops/aesctr.h>
#include <atchops/base64.h>
#include <atchops/iv.h>
#include <atlogger/atlogger.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>

#define TAG "atclient_get_sharedkey"

static int atclient_get_sharedkey_validate_arguments(const atclient *atclient, const atclient_atkey *atkey,
                                                     const char *value, const size_t valuesize, const size_t *valuelen,
                                                     const unsigned char *shared_encryption_key);

static int atclient_get_sharedkey_shared_by_me_with_other(atclient *atclient, atclient_atkey *atkey, char *value,
                                                          const size_t valuesize, size_t *valuelen,
                                                          const unsigned char *shared_encryption_key);

static int atclient_get_sharedkey_shared_by_other_with_me(atclient *atclient, atclient_atkey *atkey, char *value,
                                                          const size_t valuesize, size_t *valuelen,
                                                          const unsigned char *shared_encryption_key);

int atclient_get_sharedkey(atclient *atclient, atclient_atkey *atkey, char *value, const size_t valuesize,
                           size_t *valuelen, const unsigned char *shared_encryption_key) {
  int ret = 1;

  if ((ret = atclient_get_sharedkey_validate_arguments(atclient, atkey, value, valuesize, valuelen,
                                                       shared_encryption_key)) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atclient_get_sharedkey_validate_arguments: %d\n", ret);
    return ret;
  }

  char *client_atsign_with_at = NULL;
  char *sharedby_atsign_with_at = NULL;

  if ((ret = atclient_stringutils_atsign_with_at(atclient->atsign, &client_atsign_with_at)) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atclient_stringutils_atsign_with_at: %d\n", ret);
    goto exit;
  }

  if ((ret = atclient_stringutils_atsign_with_at(atkey->sharedby, &sharedby_atsign_with_at)) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atclient_stringutils_atsign_with_at: %d\n", ret);
    goto exit;
  }

  if (strcmp(sharedby_atsign_with_at, client_atsign_with_at) != 0) {
    if ((ret = atclient_get_sharedkey_shared_by_other_with_me(atclient, atkey, value, valuesize, valuelen,
                                                              shared_encryption_key)) != 0) {
      atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atclient_get_sharedkey_shared_by_other_with_me: %d\n", ret);
      goto exit;
    }
  } else {
    if ((ret = atclient_get_sharedkey_shared_by_me_with_other(atclient, atkey, value, valuesize, valuelen,
                                                              shared_encryption_key)) != 0) {
      atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atclient_get_sharedkey_shared_by_me_with_other: %d\n", ret);
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

static int atclient_get_sharedkey_shared_by_me_with_other(atclient *atclient, atclient_atkey *atkey, char *value,
                                                          const size_t valuesize, size_t *valuelen,
                                                          const unsigned char *shared_encryption_key) {
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
  char *atkeystr = NULL;
  char *command = NULL;

  const size_t recvsize = 4096;
  unsigned char recv[recvsize];
  size_t recvlen = 0;

  const size_t ivsize = ATCHOPS_IV_BUFFER_SIZE;
  unsigned char iv[ivsize];

  char *value_raw_encrypted = NULL;
  char *value_raw = NULL;

  const cJSON *root = NULL;

  /*
   * 3. Format atSigns
   */
  if ((ret = atclient_stringutils_atsign_with_at(atclient->atsign, &client_atsign_with_at)) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atclient_stringutils_atsign_with_at: %d\n", ret);
    goto exit;
  }

  if ((ret = atclient_stringutils_atsign_with_at(atkey->sharedwith, &recipient_atsign_with_at)) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atclient_stringutils_atsign_with_at: %d\n", ret);
    goto exit;
  }

  /*
   * 4. Get shared_encryption_key, if necessary
   */
  unsigned char shared_encryption_key_to_use[ATCHOPS_AES_256 / 8];
  memset(shared_encryption_key_to_use, 0, sizeof(unsigned char) * ATCHOPS_AES_256 / 8);
  if (shared_encryption_key != NULL) {
    memcpy(shared_encryption_key_to_use, shared_encryption_key, ATCHOPS_AES_256 / 8);
  } else {
    if ((ret = atclient_get_shared_encryption_key_shared_by_me(atclient, atkey->sharedwith,
                                                               shared_encryption_key_to_use)) != 0) {
      atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atclient_get_shared_encryption_key_shared_by_me: %d\n", ret);
      goto exit;
    }
  }

  /*
   * 5. Build `llookup:all:` command
   */
  if ((ret = atclient_atkey_to_string(atkey, &atkeystr)) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atclient_atkey_to_string: %d\n", ret);
    goto exit;
  }
  const size_t atkeystrlen = strlen(atkeystr);

  const size_t commandsize = strlen("llookup:all:") + atkeystrlen + strlen("\r\n") + 1;
  if ((command = malloc(sizeof(char) * commandsize)) == NULL) {
    ret = 1;
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "Failed to allocate memory for command\n");
    goto exit;
  }
  snprintf(command, commandsize, "llookup:all:%s\r\n", atkeystr);

  /*
   * 6. Send llookup:all: command
   */
  if ((ret = atclient_connection_send(&(atclient->atserver_connection), (unsigned char *)command, commandsize - 1, recv,
                                      recvsize, &recvlen)) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atclient_connection_send: %d\n", ret);
    goto exit;
  }

  /*
   * 7. Parse response
   */
  char *response = (char *)recv;

  if (!atclient_stringutils_starts_with(response, "data:")) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "response does not start with 'data:'\n");
    ret = 1;
    goto exit;
  }

  char *response_without_data = response + 5;

  root = cJSON_Parse(response_without_data);
  if (root == NULL) {
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

  char *metadatastr = cJSON_Print(metadata);

  if ((ret = atclient_atkey_metadata_from_jsonstr(&(atkey->metadata), metadatastr)) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atclient_atkey_metadata_from_jsonstr: %d\n", ret);
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
  if (atclient_atkey_metadata_is_ivnonce_initialized(&atkey->metadata)) {
    if ((ret = atchops_base64_decode((unsigned char *)atkey->metadata.ivnonce, strlen(atkey->metadata.ivnonce), iv,
                                     ATCHOPS_IV_BUFFER_SIZE, NULL)) != 0) {
      atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atchops_base64_decode: %d\n", ret);
      goto exit;
    }
  } else {
    memset(iv, 0, sizeof(unsigned char) * ATCHOPS_IV_BUFFER_SIZE);
  }

  /*
   * 9. Decrypt data
   */
  const char *value_raw_encrypted_base64 = data->valuestring;
  const size_t value_raw_encrypted_base64_len = strlen(data->valuestring);

  const size_t value_raw_encrypted_size = atchops_base64_decoded_size(value_raw_encrypted_base64_len);
  if ((value_raw_encrypted = malloc(sizeof(char) * value_raw_encrypted_size)) == NULL) {
    ret = 1;
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "Failed to allocate memory for value_raw_encrypted\n");
    goto exit;
  }

  memset(value_raw_encrypted, 0, sizeof(char) * value_raw_encrypted_size);
  size_t value_raw_encrypted_len = 0;
  if ((ret = atchops_base64_decode(value_raw_encrypted_base64, value_raw_encrypted_base64_len,
                                   (unsigned char *)value_raw_encrypted, value_raw_encrypted_size,
                                   &value_raw_encrypted_len)) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atchops_base64_decode: %d\n", ret);
    goto exit;
  }

  const size_t value_raw_size = atchops_aesctr_plaintext_size(value_raw_encrypted_len);
  if ((value_raw = malloc(sizeof(char) * value_raw_size)) == NULL) {
    ret = 1;
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "Failed to allocate memory for value_raw\n");
    goto exit;
  }
  memset(value_raw, 0, sizeof(char) * value_raw_size);
  size_t value_raw_len = 0;
  if ((ret = atchops_aesctr_decrypt(shared_encryption_key_to_use, ATCHOPS_AES_256, iv,
                                    (unsigned char *)value_raw_encrypted, value_raw_encrypted_len,
                                    (unsigned char *)value_raw, value_raw_size, &value_raw_len)) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atchops_aesctr_decrypt: %d\n", ret);
    goto exit;
  }

  /*
   * 10. Set value
   */
  memcpy(value, value_raw, value_raw_len);
  *valuelen = value_raw_len;

  ret = 0;
  goto exit;
exit: {
  free(client_atsign_with_at);
  free(recipient_atsign_with_at);
  free(value_raw);
  free(atkeystr);
  free(command);
  free(metadatastr);
  cJSON_Delete(root);
  return ret;
}
}

static int atclient_get_sharedkey_shared_by_other_with_me(atclient *atclient, atclient_atkey *atkey, char *value,
                                                          const size_t valuesize, size_t *valuelen,
                                                          const unsigned char *shared_encryption_key) {
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

  const size_t recvsize = 4096;
  unsigned char recv[recvsize];

  char *command = NULL;

  cJSON *root = NULL;
  char *metadatastr = NULL;

  const size_t ivsize = ATCHOPS_IV_BUFFER_SIZE;
  unsigned char iv[ivsize];

  unsigned char *value_raw_encryted = NULL;
  unsigned char *value_raw = NULL;

  /*
   * 3. Format atSigns
   */
  if ((ret = atclient_stringutils_atsign_with_at(atkey->sharedby, &sender_atsign_with_at)) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atclient_stringutils_atsign_with_at: %d\n", ret);
    goto exit;
  }

  if ((ret = atclient_stringutils_atsign_with_at(atkey->sharedwith, &recipient_atsign_with_at)) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atclient_stringutils_atsign_with_at: %d\n", ret);
    goto exit;
  }

  /*
   * 4. Get shared_encryption_key, if necessary
   */
  const size_t shared_encryption_key_size = ATCHOPS_AES_256 / 8;
  unsigned char shared_encryption_key_to_use[shared_encryption_key_size];
  if (shared_encryption_key == NULL) {
    if ((ret = atclient_get_shared_encryption_key_shared_by_other(atclient, atkey->sharedby,
                                                                  shared_encryption_key_to_use)) != 0) {
      atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atclient_get_shared_encryption_key_shared_by_other: %d\n", ret);
      goto exit;
    }
  } else {
    memcpy(shared_encryption_key_to_use, shared_encryption_key, shared_encryption_key_size);
  }

  /*
   * 5. Build lookup: command
   */
  size_t commandsize = strlen("lookup:") + strlen(atkey->key);
  bool namespace_exists = atclient_atkey_is_namespacestr_initialized(atkey);
  if (namespace_exists) {
    commandsize += strlen(".") + strlen(atkey->namespacestr);
  }
  commandsize += strlen(sender_atsign_with_at) + strlen("\r\n") + 1;
  if ((command = (char *)malloc(sizeof(char) * commandsize)) == NULL) {
    ret = 1;
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "Failed to allocate memory for command\n");
    goto exit;
  }
  if (namespace_exists) {
    snprintf(command, commandsize, "lookup:%s.%s%s\r\n", atkey->key, atkey->namespacestr, sender_atsign_with_at);
  } else {
    snprintf(command, commandsize, "lookup:%s%s\r\n", atkey->key, sender_atsign_with_at);
  }

  /*
   * 6. Send lookup: command
   */
  memset(recv, 0, sizeof(unsigned char) * recvsize);
  size_t recvlen = 0;
  if ((ret = atclient_connection_send(&(atclient->atserver_connection), (unsigned char *)command, commandsize - 1, recv,
                                      recvsize, &recvlen)) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atclient_connection_send: %d\n", ret);
    goto exit;
  }

  /*
   * 7. Parse response
   */
  char *response = (char *)recv;

  // Truncate response : "data:"
  if (!atclient_stringutils_starts_with(response, "data:")) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "response does not start with 'data:'\n");
    ret = 1;
    goto exit;
  }

  char *response_without_data = response + 5;

  root = cJSON_Parse(response);
  if (root == NULL) {
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

  metadatastr = cJSON_Print(metadata);

  if ((ret = atclient_atkey_metadata_from_jsonstr(&(atkey->metadata), metadatastr)) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atclient_atkey_metadata_from_jsonstr: %d\n", ret);
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
  if (atclient_atkey_metadata_is_ivnonce_initialized(&atkey->metadata)) {
    if ((ret = atchops_base64_decode((unsigned char *)atkey->metadata.ivnonce, strlen(atkey->metadata.ivnonce), iv,
                                     ivsize, NULL)) != 0) {
      atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atchops_base64_decode: %d\n", ret);
      goto exit;
    }
  } else {
    memset(iv, 0, sizeof(unsigned char) * ATCHOPS_IV_BUFFER_SIZE);
  }

  /*
   * 9. Decrypt data
   */

  const unsigned char *value_raw_encrypted_base64 = (unsigned char *)data->valuestring;
  const size_t value_raw_encrypted_base64_len = strlen(data->valuestring);

  // 9a. base64 decode
  const value_raw_encryted_size = atchops_base64_decoded_size(value_raw_encrypted_base64_len);
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
  const size_t value_raw_size = atchops_aesctr_plaintext_size(value_raw_encryted_len);
  if ((value_raw = malloc(sizeof(unsigned char) * value_raw_size)) == NULL) {
    ret = 1;
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "Failed to allocate memory for value_raw\n");
    goto exit;
  }
  memset(value_raw, 0, sizeof(unsigned char) * value_raw_size);
  size_t value_raw_len = 0;
  if ((ret = atchops_aesctr_decrypt(shared_encryption_key_to_use, ATCHOPS_AES_256, iv, value_raw_encryted,
                                    value_raw_encryted_len, (unsigned char *)value_raw, value_raw_size,
                                    &value_raw_len)) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atchops_aesctr_decrypt: %d\n", ret);
    goto exit;
  }

  /*
   * 10. Set value
   */
  memcpy(value, value_raw, value_raw_len);
  *valuelen = value_raw_len;

  ret = 0;
  goto exit;
exit: {
  free(sender_atsign_with_at);
  free(recipient_atsign_with_at);
  free(value_raw_encryted);
  free(value_raw);
  free(command);
  free(metadatastr);
  cJSON_Delete(root);
  return ret;
}
}

static int atclient_get_sharedkey_validate_arguments(const atclient *atclient, const atclient_atkey *atkey,
                                                     const char *value, const size_t valuesize, const size_t *valuelen,
                                                     const unsigned char *shared_encryption_key) {
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
        "atclient_get_sharedkey cannot be called from an async_read atclient, it will cause a race condition\n");
    goto exit;
  }

  if (atkey == NULL) {
    ret = 1;
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atkey is NULL\n");
    goto exit;
  }

  if (atclient_atkey_get_type(atkey) != ATCLIENT_ATKEY_TYPE_SHAREDKEY) {
    ret = 1;
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atkey is not a shared key\n");
    goto exit;
  }

  if (!atclient_atkey_is_key_initialized(atkey) || strlen(atkey->key) <= 0) {
    ret = 1;
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "key is not initialized or is empty\n");
    goto exit;
  }

  if (!atclient_atkey_is_sharedby_initialized(atkey) || strlen(atkey->key) <= 0) {
    ret = 1;
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "sharedby is not initialized or is empty\n");
    goto exit;
  }

  if (!atclient_atkey_is_sharedwith_initialized(atkey) || strlen(atkey->key) <= 0) {
    ret = 1;
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "sharedwith is not initialized or is empty\n");
    goto exit;
  }

  if (value == NULL) {
    ret = 1;
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "value is NULL\n");
    goto exit;
  }

  if (valuesize == 0) {
    ret = 1;
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "valuesize is 0\n");
    goto exit;
  }

  if (valuelen == NULL) {
    ret = 1;
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "valuelen is NULL\n");
    goto exit;
  }

  ret = 0;
exit: { return ret; }
}
