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

static int
atclient_get_sharedkey_shared_by_me_with_other(atclient *atclient, atclient_atkey *atkey, char *value,
                                               const size_t valuelen, size_t *valueolen, char *shared_enc_key,
                                               const bool create_new_encryption_key_shared_by_me_if_not_found);

static int atclient_get_sharedkey_shared_by_other_with_me(atclient *atclient, atclient_atkey *atkey, char *value,
                                                          const size_t valuelen, size_t *valueolen,
                                                          char *shared_enc_key);

int atclient_get_sharedkey(atclient *atclient, atclient_atkey *atkey, char *value, const size_t valuelen,
                           size_t *valueolen, char *shared_enc_key,
                           const bool create_new_encryption_key_shared_by_me_if_not_found) {
  int ret = 1;

  if (atkey->atkeytype != ATCLIENT_ATKEY_TYPE_SHAREDKEY) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atkey->atkeytype != ATCLIENT_ATKEY_TYPE_SHAREDKEY\n");
    return ret;
  }

  if (strncmp(atkey->sharedby.str, atclient->atsign.atsign, atkey->sharedby.olen) != 0) {
    //  && (!atkey->metadata.iscached && !atkey->metadata.ispublic)
    ret = atclient_get_sharedkey_shared_by_other_with_me(atclient, atkey, value, valuelen, valueolen, shared_enc_key);
    if (ret != 0) {
      atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atclient_get_sharedkey_shared_by_other_with_me: %d\n",
                            ret);
      goto exit;
    }
  } else {
    ret = atclient_get_sharedkey_shared_by_me_with_other(atclient, atkey, value, valuelen, valueolen, shared_enc_key,
                                                         false);
    if (ret != 0) {
      atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atclient_get_sharedkey_shared_by_me_with_other: %d\n",
                            ret);
      goto exit;
    }
  }

  goto exit;
exit: { return ret; }
}

static int
atclient_get_sharedkey_shared_by_me_with_other(atclient *atclient, atclient_atkey *atkey, char *value,
                                               const size_t valuelen, size_t *valueolen, char *shared_enc_key,
                                               const bool create_new_encryption_key_shared_by_me_if_not_found) {
  int ret = 1;
  short enc_key_mem = 0;

  char *atkey_str_buff = NULL;
  char *command = NULL;
  char *response_prefix = NULL;
  unsigned char *recv = NULL;

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
    atclient_atsign recipient;
    ret = atclient_atsign_init(&recipient, atkey->sharedwith.str);
    if (ret != 0) {
      goto exit;
    }
    ret = atclient_get_shared_encryption_key_shared_by_me(atclient, &recipient, enc_key,
                                                          create_new_encryption_key_shared_by_me_if_not_found);
    if (ret != 0) {
      atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atclient_get_encryption_key_shared_by_me: %d\n", ret);
      goto exit;
    }
  }

  ret = atchops_base64_decode(enc_key, strlen(enc_key), enckey, enckeysize, &enckeylen);
  if (ret != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atchops_base64_decode: %d\n", ret);
    goto exit;
  }

  // atclient_atkey_to_string buffer
  const size_t atkey_str_buf_len = 4096;
  atkey_str_buff = calloc(atkey_str_buf_len, sizeof(char));
  size_t atkey_out_len = 0;

  ret = atclient_atkey_to_string(atkey, atkey_str_buff, atkey_str_buf_len, &atkey_out_len);
  if (ret != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atclient_atkey_to_string: %d\n", ret);
    goto exit;
  }

  // build command
  // command_prefix = "llookup:all:"
  const short command_prefix_len = 12;

  const size_t command_len = command_prefix_len + atkey_out_len + 3;
  command = malloc(command_len * sizeof(char));
  snprintf(command, command_len, "llookup:all:%s\r\n", atkey_str_buff);

  // send command and recv response
  const size_t recvlen = 4096;
  recv = calloc(recvlen, sizeof(unsigned char));
  memset(recv, 0, sizeof(unsigned char) * recvlen);
  size_t recv_olen = 0;

  ret = atclient_connection_send(&(atclient->secondary_connection), (unsigned char *)command, strlen((char *)command),
                                 recv, recvlen, &recv_olen);
  if (ret != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atclient_connection_send: %d\n", ret);
    goto exit;
  }

  char *response = (char *)recv;
  short atsign_with_at_len = (short)strlen(atclient->atsign.atsign);

  // Truncate response: "@" + myatsign + "@"
  int response_prefix_len = atsign_with_at_len + 2;
  response_prefix = malloc(response_prefix_len * sizeof(char));
  snprintf(response_prefix, response_prefix_len, "@%s@", atclient->atsign.without_prefix_str);

  if (atclient_stringutils_starts_with(response, recvlen, response_prefix, response_prefix_len)) {
    response = response + response_prefix_len;
  }

  if (atclient_stringutils_ends_with(response, recvlen, response_prefix, response_prefix_len)) {
    response[strlen(response) - response_prefix_len - 1] = '\0';
  }

  // Truncate response : "data:"
  if (atclient_stringutils_starts_with(response, recvlen, "data:", 5)) {
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

    ret = atclient_atkey_metadata_from_jsonstr(&(atkey->metadata), metadatastr, strlen(metadatastr));
    if (ret != 0) {
      atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atclient_atkey_metadata_from_jsonstr: %d\n", ret);
      goto exit;
    }

    // manage IV
    if (atclient_atkey_metadata_is_ivnonce_initialized(&atkey->metadata)) {
      size_t ivolen;
      ret = atchops_base64_decode((unsigned char *)atkey->metadata.ivnonce.str, atkey->metadata.ivnonce.olen, iv,
                                  ATCHOPS_IV_BUFFER_SIZE, &ivolen);
      if (ret != 0) {
        atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atchops_base64_decode: %d\n", ret);
        goto exit;
      }

      if (ivolen != ATCHOPS_IV_BUFFER_SIZE) {
        ret = 1;
        atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "ivolen != ivlen (%d != %d)\n", ivolen,
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
    memset(valueraw, 0, sizeof(char) * valuerawsize);
    size_t valuerawlen = 0;

    ret = atchops_base64_decode((unsigned char *)data->valuestring, strlen(data->valuestring), (unsigned char *)valueraw,
                                valuerawsize, &valuerawlen);
    if (ret != 0) {
      atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atchops_base64_decode: %d\n", ret);
      goto exit;
    }

    // decrypt response data
    ret = atchops_aesctr_decrypt(enckey, ATCHOPS_AES_256, iv, valueraw, valuerawlen, value, valuelen, valueolen);
    if (ret != 0) {
      atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atchops_aesctr_decrypt: %d\n", ret);
      goto exit;
    }
  }

  ret = 0;
  goto exit;
exit: {
  if (enc_key_mem)
    free(enc_key);
  if (atkey_str_buff)
    free(atkey_str_buff);
  if (command)
    free(command);
  if (recv)
    free(recv);
  if (response_prefix)
    free(response_prefix);
  return ret;
}
}

static int atclient_get_sharedkey_shared_by_other_with_me(atclient *atclient, atclient_atkey *atkey, char *value,
                                                          const size_t valuelen, size_t *valueolen,
                                                          char *shared_enc_key) {
  int ret = 1;
  char *command = NULL;
  unsigned char *recv = NULL;
  char *response_prefix = NULL;

  const size_t enckeysize = ATCHOPS_AES_256 / 8;
  unsigned char enckey[enckeysize];
  memset(enckey, 0, sizeof(unsigned char) * enckeysize);
  size_t enckeylen = 0;

  char *enc_key = shared_enc_key;
  if (enc_key == NULL) {
    enc_key = malloc(45);
    atclient_atsign recipient;
    ret = atclient_atsign_init(&recipient, atkey->sharedby.str);
    if (ret != 0) {
      goto exit;
    }
    ret = atclient_get_shared_encryption_key_shared_by_other(atclient, &recipient, enc_key);
    if (ret != 0) {
      atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atclient_get_encryption_key_shared_by_me: %d\n", ret);
      goto exit;
    }
  }

  char *namespace = "";
  size_t namespace_len = 0;
  short extra_point_len = 0; // "." before namespace

  if (atkey->namespacestr.str != NULL && atkey->namespacestr.str[0] != '\0') {
    namespace = atkey->namespacestr.str;
    namespace_len = atkey->namespacestr.olen;
    extra_point_len = 1;
  }

  // build command
  // command_prefix = "lookup:"
  const short command_prefix_len = 11;
  const size_t command_len =
      command_prefix_len + atkey->name.olen + extra_point_len + namespace_len + atkey->sharedby.olen + 3;
  command = calloc(command_len, sizeof(char));
  snprintf(command, command_len, "lookup:all:%s%s%s%s\r\n", atkey->name.str, extra_point_len ? "." : "", namespace,
           atkey->sharedby.str);

  // send command and recv response
  const size_t recvlen = 4096;
  recv = calloc(recvlen, sizeof(unsigned char));
  memset(recv, 0, sizeof(unsigned char) * recvlen);
  size_t recv_olen = 0;

  ret = atclient_connection_send(&(atclient->secondary_connection), (unsigned char *)command, strlen((char *)command),
                                 recv, recvlen, &recv_olen);
  if (ret != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atclient_connection_send: %d\n", ret);
    goto exit;
  }

  char *response = (char *)recv;
  short atsign_with_at_len = (short)strlen(atclient->atsign.atsign);

  // Truncate response: "@" + myatsign + "@"
  int response_prefix_len = atsign_with_at_len + 2;
  response_prefix = malloc(response_prefix_len * sizeof(char));
  snprintf(response_prefix, response_prefix_len, "@%s@", atclient->atsign.without_prefix_str);

  if (atclient_stringutils_starts_with(response, recvlen, response_prefix, response_prefix_len)) {
    response = response + response_prefix_len;
  }

  if (atclient_stringutils_ends_with(response, recvlen, response_prefix, response_prefix_len)) {
    response[strlen(response) - response_prefix_len - 1] = '\0';
  }

  // Truncate response : "data:"
  if (atclient_stringutils_starts_with(response, recvlen, "data:", 5)) {
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

    ret = atclient_atkey_metadata_from_jsonstr(&(atkey->metadata), metadatastr, strlen(metadatastr));
    if (ret != 0) {
      atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atclient_atkey_metadata_from_jsonstr: %d\n", ret);
      goto exit;
    }

    // manage IV
    if (atclient_atkey_metadata_is_ivnonce_initialized(&atkey->metadata)) {
      size_t ivolen;
      ret = atchops_base64_decode((unsigned char *)atkey->metadata.ivnonce.str, atkey->metadata.ivnonce.olen, iv,
                                  ATCHOPS_IV_BUFFER_SIZE, &ivolen);
      if (ret != 0) {
        atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atchops_base64_decode: %d\n", ret);
        goto exit;
      }

      if (ivolen != ATCHOPS_IV_BUFFER_SIZE) {
        ret = 1;
        atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "ivolen != ivlen (%d != %d)\n", ivolen,
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

    // decrypt response data
    ret = atchops_base64_decode(enc_key, strlen(enc_key), enckey, enckeysize, &enckeylen);
    if (ret != 0) {
      atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atchops_base64_decode: %d\n", ret);
      goto exit;
    }

    ret = atchops_aesctr_decrypt(enckey, ATCHOPS_AES_256, iv, (unsigned char *)data->valuestring,
                                 strlen(data->valuestring), (unsigned char *)value, valuelen, valueolen);
    if (ret != 0) {
      atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atchops_aesctr_decrypt: %d\n", ret);
      goto exit;
    }
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
  return ret;
}
}