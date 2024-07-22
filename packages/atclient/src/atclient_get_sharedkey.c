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
                                                     const char *shared_enc_key) {
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

static int
atclient_get_sharedkey_shared_by_me_with_other(atclient *atclient, atclient_atkey *atkey, char *value,
                                               const size_t valuesize, size_t *valuelen, char *shared_enc_key,
                                               const bool create_new_encryption_key_shared_by_me_if_not_found);

static int atclient_get_sharedkey_shared_by_other_with_me(atclient *atclient, atclient_atkey *atkey, char *value,
                                                          const size_t valuesize, size_t *valuelen,
                                                          char *shared_enc_key);

int atclient_get_sharedkey(atclient *atclient, atclient_atkey *atkey, char *value, const size_t valuesize,
                           size_t *valuelen, char *shared_enc_key,
                           const bool create_new_encryption_key_shared_by_me_if_not_found) {
  int ret = 1;

  if ((ret = atclient_get_sharedkey_validate_arguments(atclient, atkey, value, valuesize, valuelen, shared_enc_key)) !=
      0) {
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
    ret = atclient_get_sharedkey_shared_by_other_with_me(atclient, atkey, value, valuesize, valuelen, shared_enc_key);
    if (ret != 0) {
      atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atclient_get_sharedkey_shared_by_other_with_me: %d\n", ret);
      goto exit;
    }
  } else {
    ret = atclient_get_sharedkey_shared_by_me_with_other(atclient, atkey, value, valuesize, valuelen, shared_enc_key,
                                                         false);
    if (ret != 0) {
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

static int
atclient_get_sharedkey_shared_by_me_with_other(atclient *atclient, atclient_atkey *atkey, char *value,
                                               const size_t valuesize, size_t *valuelen, char *shared_enc_key,
                                               const bool create_new_encryption_key_shared_by_me_if_not_found) {
  int ret = 1;
  short enc_key_mem = 0;

  char *atkeystr = NULL;
  char *command = NULL;
  char *response_prefix = NULL;
  unsigned char *recv = NULL;
  char *client_atsign_with_at = NULL;
  char *client_atsign_without_at = NULL;

  const size_t enckeysize = ATCHOPS_AES_256 / 8;
  unsigned char enckey[enckeysize];
  memset(enckey, 0, sizeof(unsigned char) * enckeysize);
  size_t enckeylen = 0;

  char *valueraw = NULL;

  // check shared key
  char *enc_key = shared_enc_key;
  if (enc_key == NULL) {
    enc_key_mem = 1;
    enc_key = malloc(45);
    if (enc_key == NULL) {
      ret = 1;
      atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "Failed to allocate memory for enc_key\n");
      goto exit;
    }
    char *recipient = atkey->sharedwith;
    if ((ret = atclient_get_shared_encryption_key_shared_by_me(
             atclient, recipient, enc_key, create_new_encryption_key_shared_by_me_if_not_found)) != 0) {
      atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atclient_get_encryption_key_shared_by_me: %d\n", ret);
      goto exit;
    }
  }

  if ((ret = atclient_stringutils_atsign_with_at(atclient->atsign, &client_atsign_with_at)) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atclient_stringutils_atsign_with_at: %d\n", ret);
    goto exit;
  }

  if ((ret = atclient_stringutils_atsign_without_at(atclient->atsign, &client_atsign_without_at)) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atclient_stringutils_atsign_without_at: %d\n", ret);
    goto exit;
  }

  ret = atchops_base64_decode((unsigned char *)enc_key, strlen(enc_key), enckey, enckeysize, &enckeylen);
  if (ret != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atchops_base64_decode: %d\n", ret);
    goto exit;
  }

  ret = atclient_atkey_to_string(atkey, &atkeystr);
  if (ret != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atclient_atkey_to_string: %d\n", ret);
    goto exit;
  }
  const size_t atkeystrlen = strlen(atkeystr);

  // build command
  // command_prefix = "llookup:all:"
  const size_t commandsize = strlen("llookup:all:") + atkeystrlen + strlen("\r\n") + 1;
  command = malloc(commandsize * sizeof(char));
  if (command == NULL) {
    ret = 1;
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "Failed to allocate memory for command\n");
    goto exit;
  }
  snprintf(command, commandsize, "llookup:all:%s\r\n", atkeystr);

  // send command and recv response
  const size_t recvsize = 4096;
  recv = calloc(recvsize, sizeof(unsigned char));
  memset(recv, 0, sizeof(unsigned char) * recvsize);
  size_t recvlen = 0;

  ret = atclient_connection_send(&(atclient->atserver_connection), (unsigned char *)command, commandsize - 1, recv,
                                 recvsize, &recvlen);
  if (ret != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atclient_connection_send: %d\n", ret);
    goto exit;
  }

  char *response = (char *)recv;
  short atsign_with_at_len = (short)strlen(client_atsign_with_at);

  // Truncate response: "@" + myatsign + "@"
  int response_prefix_len = atsign_with_at_len + 2;
  response_prefix = malloc(response_prefix_len * sizeof(char));
  memset(response_prefix, 0, sizeof(char) * response_prefix_len);
  if (response_prefix == NULL) {
    ret = 1;
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "Failed to allocate memory for response_prefix\n");
    goto exit;
  }
  snprintf(response_prefix, response_prefix_len, "@%s@", client_atsign_without_at);

  if (atclient_stringutils_starts_with(response, response_prefix)) {
    response = response + response_prefix_len;
  }

  if (atclient_stringutils_ends_with(response, response_prefix)) {
    response[strlen(response) - response_prefix_len - 1] = '\0';
  }

  // Truncate response : "data:"
  if (atclient_stringutils_starts_with(response, "data:")) {
    response = response + 5;

    unsigned char iv[ATCHOPS_IV_BUFFER_SIZE];
    const cJSON *root = cJSON_Parse(response);
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

    ret = atclient_atkey_metadata_from_jsonstr(&(atkey->metadata), metadatastr);
    if (ret != 0) {
      atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atclient_atkey_metadata_from_jsonstr: %d\n", ret);
      goto exit;
    }

    // manage IV
    if (atclient_atkey_metadata_is_ivnonce_initialized(&atkey->metadata)) {
      size_t ivlen;
      ret = atchops_base64_decode((unsigned char *)atkey->metadata.ivnonce, strlen(atkey->metadata.ivnonce), iv,
                                  ATCHOPS_IV_BUFFER_SIZE, &ivlen);
      if (ret != 0) {
        atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atchops_base64_decode: %d\n", ret);
        goto exit;
      }

      if (ivlen != ATCHOPS_IV_BUFFER_SIZE) {
        ret = 1;
        atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "ivlen != ATCHOPS_IV_BUFFER_SIZE (%d != %d)\n", ivlen,
                     ATCHOPS_IV_BUFFER_SIZE);
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

    const size_t valuerawsize = strlen(data->valuestring) * 4; // most likely enough space after base64 decode
    valueraw = malloc(sizeof(char) * valuerawsize);
    if (valueraw == NULL) {
      ret = 1;
      atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "Failed to allocate memory for valueraw\n");
      goto exit;
    }
    memset(valueraw, 0, sizeof(char) * valuerawsize);
    size_t valuerawlen = 0;

    ret = atchops_base64_decode((unsigned char *)data->valuestring, strlen(data->valuestring),
                                (unsigned char *)valueraw, valuerawsize, &valuerawlen);
    if (ret != 0) {
      atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atchops_base64_decode: %d\n", ret);
      goto exit;
    }

    // decrypt response data
    ret = atchops_aesctr_decrypt(enckey, ATCHOPS_AES_256, iv, (unsigned char *)valueraw, valuerawlen,
                                 (unsigned char *)value, valuesize, valuelen);
    if (ret != 0) {
      atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atchops_aesctr_decrypt: %d\n", ret);
      goto exit;
    }
  } else {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "response does not start with 'data:'\n");
    ret = 1;
    goto exit;
  }

  ret = 0;
  goto exit;
exit: {
  free(enc_key);
  free(command);
  free(recv);
  free(atkeystr);
  return ret;
}
}

static int atclient_get_sharedkey_shared_by_other_with_me(atclient *atclient, atclient_atkey *atkey, char *value,
                                                          const size_t valuesize, size_t *valuelen,
                                                          char *shared_enc_key) {
  int ret = 1;
  char *command = NULL;
  unsigned char *recv = NULL;
  char *response_prefix = NULL;
  char *client_atsign_with_at = NULL;
  char *client_atsign_without_at = NULL;

  const size_t enckeysize = ATCHOPS_AES_256 / 8;
  unsigned char enckey[enckeysize];
  memset(enckey, 0, sizeof(unsigned char) * enckeysize);
  size_t enckeylen = 0;

  const size_t valuerawsize = valuesize * 4;
  unsigned char valueraw[valuerawsize];
  memset(valueraw, 0, sizeof(unsigned char) * valuerawsize);
  size_t valuerawlen = 0;

  char *enc_key = shared_enc_key;
  if (enc_key == NULL) {
    enc_key = malloc(45);
    if (enc_key == NULL) {
      ret = 1;
      atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "Failed to allocate memory for enc_key\n");
      goto exit;
    }
    char *recipient = atkey->sharedby;
    if ((ret = atclient_get_shared_encryption_key_shared_by_other(atclient, recipient, enc_key)) != 0) {
      atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atclient_get_encryption_key_shared_by_me: %d\n", ret);
      goto exit;
    }
  }

  if ((ret = atclient_stringutils_atsign_with_at(atclient->atsign, &client_atsign_with_at)) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atclient_stringutils_atsign_with_at: %d\n", ret);
    goto exit;
  }

  if ((ret = atclient_stringutils_atsign_without_at(atclient->atsign, &client_atsign_without_at)) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atclient_stringutils_atsign_without_at: %d\n", ret);
    goto exit;
  }

  char *namespace = "";
  size_t namespace_len = 0;
  short extra_point_len = 0; // "." before namespace

  if (atkey->namespacestr != NULL && atkey->namespacestr[0] != '\0') {
    namespace = atkey->namespacestr;
    namespace_len = strlen(atkey->namespacestr);
    extra_point_len = 1;
  }

  // build command
  // command_prefix = "lookup:"
  const short command_prefix_len = 11;
  const size_t command_len =
      command_prefix_len + strlen(atkey->key) + extra_point_len + namespace_len + strlen(atkey->sharedby) + 3;
  command = calloc(command_len, sizeof(char));
  snprintf(command, command_len, "lookup:all:%s%s%s%s\r\n", atkey->key, extra_point_len ? "." : "", namespace,
           atkey->sharedby);

  // send command and recv response
  const size_t recvsize = 4096;
  recv = calloc(recvsize, sizeof(unsigned char));
  size_t recvlen = 0;

  ret = atclient_connection_send(&(atclient->atserver_connection), (unsigned char *)command, strlen((char *)command),
                                 recv, recvsize, &recvlen);
  if (ret != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atclient_connection_send: %d\n", ret);
    goto exit;
  }

  char *response = (char *)recv;
  short atsign_with_at_len = (short)strlen(client_atsign_with_at);

  // Truncate response: "@" + myatsign + "@"
  int response_prefix_len = atsign_with_at_len + 2;
  response_prefix = malloc(response_prefix_len * sizeof(char));
  if (response_prefix == NULL) {
    ret = 1;
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "Failed to allocate memory for response_prefix\n");
    goto exit;
  }
  snprintf(response_prefix, response_prefix_len, "@%s@", client_atsign_without_at);

  if (atclient_stringutils_starts_with(response, response_prefix)) {
    response = response + response_prefix_len;
  }

  if (atclient_stringutils_ends_with(response, response_prefix)) {
    response[strlen(response) - response_prefix_len - 1] = '\0';
  }

  // Truncate response : "data:"
  if (atclient_stringutils_starts_with(response, "data:")) {
    response = response + 5;

    unsigned char iv[ATCHOPS_IV_BUFFER_SIZE];
    const cJSON *root = cJSON_Parse(response);
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

    ret = atclient_atkey_metadata_from_jsonstr(&(atkey->metadata), metadatastr);
    if (ret != 0) {
      atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atclient_atkey_metadata_from_jsonstr: %d\n", ret);
      goto exit;
    }

    // manage IV
    if (atclient_atkey_metadata_is_ivnonce_initialized(&atkey->metadata)) {
      size_t ivlen;
      ret = atchops_base64_decode((unsigned char *)atkey->metadata.ivnonce, strlen(atkey->metadata.ivnonce), iv,
                                  ATCHOPS_IV_BUFFER_SIZE, &ivlen);
      if (ret != 0) {
        atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atchops_base64_decode: %d\n", ret);
        goto exit;
      }

      if (ivlen != ATCHOPS_IV_BUFFER_SIZE) {
        ret = 1;
        atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "ivlen != ivlen (%d != %d)\n", ivlen, ATCHOPS_IV_BUFFER_SIZE);
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

    // decrypt response data
    ret = atchops_base64_decode((unsigned char *)enc_key, strlen(enc_key), enckey, enckeysize, &enckeylen);
    if (ret != 0) {
      atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atchops_base64_decode: %d\n", ret);
      goto exit;
    }

    ret = atchops_base64_decode((unsigned char *)data->valuestring, strlen(data->valuestring), valueraw, valuerawsize,
                                &valuerawlen);
    if ((ret != 0) || (valuerawlen == 0)) {
      atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atchops_base64_decode: %d | or valuerawlen: %d\n", ret,
                   valuerawlen);
      goto exit;
    }

    ret = atchops_aesctr_decrypt(enckey, ATCHOPS_AES_256, iv, valueraw, valuerawlen, (unsigned char *)value, valuesize,
                                 valuelen);
    if (ret != 0) {
      atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atchops_aesctr_decrypt: %d\n", ret);
      goto exit;
    }
  } else {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "response does not start with 'data:'\n");
    ret = 1;
    goto exit;
  }

  ret = 0;
  goto exit;
exit: {
  if (command)
    free(command);
  if (recv)
    free(recv);
  if (response_prefix)
    free(response_prefix);
  free(client_atsign_with_at);
  return ret;
}
}
