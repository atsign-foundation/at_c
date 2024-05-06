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

static int atclient_get_sharedkey_shared_by_me_with_other(atclient *atclient, atclient_atkey *atkey, char *value,
                                                          const size_t valuesize, size_t *valuelen,
                                                          unsigned char *sharedenckey);

static int atclient_get_sharedkey_shared_by_other_with_me(atclient *atclient, atclient_atkey *atkey, char *value,
                                                          const size_t valuesize, size_t *valuelen,
                                                          unsigned char *sharedenckey);

int atclient_get_sharedkey(atclient *atclient, atclient_atkey *atkey, char *value, const size_t valuesize,
                           size_t *valuelen, unsigned char *sharedenckey) {
  int ret = 1;

  if (atkey->atkeytype != ATCLIENT_ATKEY_TYPE_SHAREDKEY) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atkey->atkeytype != ATCLIENT_ATKEY_TYPE_SHAREDKEY\n");
    return ret;
  }

  if (strncmp(atkey->sharedby.str, atclient->atsign.atsign, atkey->sharedby.len) != 0) {
    // shared by me with other, it's in my atServer
    ret = atclient_get_sharedkey_shared_by_other_with_me(atclient, atkey, value, valuesize, valuelen, sharedenckey);
    if (ret != 0) {
      atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atclient_get_sharedkey_shared_by_other_with_me: %d\n", ret);
      goto exit;
    }
  } else {
    // shared by other with me, it's in the other atServer
    ret = atclient_get_sharedkey_shared_by_me_with_other(atclient, atkey, value, valuesize, valuelen, sharedenckey);
    if (ret != 0) {
      atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atclient_get_sharedkey_shared_by_me_with_other: %d\n", ret);
      goto exit;
    }
  }

  goto exit;
exit: { return ret; }
}

static int atclient_get_sharedkey_shared_by_me_with_other(atclient *atclient, atclient_atkey *atkey, char *value,
                                                          const size_t valuesize, size_t *valuelen,
                                                          unsigned char *sharedenckey) {
  int ret = 1;

  cJSON *root = NULL;
  char *command = NULL;

  const size_t enckeysize = ATCHOPS_AES_256 / 8;
  unsigned char enckey[enckeysize];
  memset(enckey, 0, sizeof(unsigned char) * enckeysize);
  size_t enckeylen = 0;

  const size_t recvsize = 4096;
  unsigned char recv[recvsize];
  memset(recv, 0, sizeof(unsigned char) * recvsize);
  size_t recvlen = 0;

  const size_t atkeystrsize = atclient_atkey_strlen((const atclient_atkey *)atkey);
  char atkeystr[atkeystrsize];
  memset(atkeystr, 0, sizeof(char) * atkeystrsize);
  size_t atkeystrlen = 0;

  const size_t valuerawsize = valuesize * 4; // most likely enough space after base64 decode
  unsigned char valueraw[valuerawsize];
  memset(valueraw, 0, sizeof(unsigned char) * valuerawsize);
  size_t valuerawlen = 0;

  if (sharedenckey == NULL) {
    ret =
        atclient_get_shared_encryption_key_shared_by_me(atclient, atkey->sharedwith.str, atkey->sharedwith.len, enckey);
    if (ret != 0) {
      atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atclient_get_shared_encryption_key_shared_by_me: %d\n", ret);
      goto exit;
    }
  } else {
    memcpy(enckey, sharedenckey, enckeysize);
  }

  if ((ret = atclient_atkey_to_string(atkey, atkeystr, atkeystrsize, &atkeystrlen)) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atclient_atkey_to_string: %d\n", ret);
    goto exit;
  }

  // build command
  const size_t commandsize = strlen("llookup:all:") + atkeystrlen + strlen("\r\n") + 1;
  command = malloc(sizeof(char) * commandsize);
  memset(command, 0, sizeof(char) * commandsize);
  snprintf(command, commandsize, "llookup:all:%.*s\r\n", (int)atkeystrlen, atkeystr);

  // send command and recv response
  ret = atclient_connection_send(&(atclient->secondary_connection), (unsigned char *)command, commandsize - 1, recv,
                                 recvsize, &recvlen);
  if (ret != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atclient_connection_send: %d\n", ret);
    goto exit;
  }

  // Truncate response : "data:"
  if (atclient_stringutils_starts_with((const char *)recv, recvlen, "data:", strlen("data:"))) {
    const char *response = recv + strlen("data:");

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

    atclient_atkey_metadata_from_cjson_node(&(atkey->metadata), metadata);

    // manage IV
    if (atclient_atkey_metadata_is_ivnonce_initialized(&atkey->metadata)) {
      size_t ivlen;
      ret = atchops_base64_decode((unsigned char *)atkey->metadata.ivnonce.str, atkey->metadata.ivnonce.len, iv,
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

    ret = atchops_base64_decode((unsigned char *)data->valuestring, strlen(data->valuestring), valueraw, valuerawsize,
                                &valuerawlen);
    if (ret != 0) {
      atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atchops_base64_decode: %d\n", ret);
      goto exit;
    }
    // log what we're abuot to decrypt
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_DEBUG, "valueraw: %.*s\n", (int)valuerawlen, valueraw);

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
  if (root != NULL) {
    cJSON_Delete(root);
  }
  free(command);
  return ret;
}
}

static int atclient_get_sharedkey_shared_by_other_with_me(atclient *atclient, atclient_atkey *atkey, char *value,
                                                          const size_t valuesize, size_t *valuelen,
                                                          unsigned char *sharedenckey) {
  int ret = 1;

  char *command = NULL;
  cJSON *root = NULL;

  const size_t enckeysize = ATCHOPS_AES_256 / 8;
  unsigned char enckey[enckeysize];
  memset(enckey, 0, sizeof(unsigned char) * enckeysize);
  size_t enckeylen = 0;

  const size_t valuerawsize = valuesize * 4;
  unsigned char valueraw[valuerawsize];
  memset(valueraw, 0, sizeof(unsigned char) * valuerawsize);
  size_t valuerawlen = 0;

  const size_t recvsize = 4096;
  unsigned char recv[recvsize];
  memset(recv, 0, sizeof(unsigned char) * recvsize);
  size_t recvlen = 0;

  if (sharedenckey == NULL) {
    ret =
        atclient_get_shared_encryption_key_shared_by_other(atclient, atkey->sharedby.str, atkey->sharedby.len, enckey);
    if (ret != 0) {
      atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atclient_get_encryption_key_shared_by_me: %d\n", ret);
      goto exit;
    }
  } else {
    memcpy(enckey, sharedenckey, enckeysize);
  }

  char *namespacestr = "";
  size_t namespacelen = 0;
  short extra_point_len = 0; // "." before namespace

  if (atkey->namespacestr.str != NULL && atkey->namespacestr.str[0] != '\0') {
    namespacestr = atkey->namespacestr.str;
    namespacelen = atkey->namespacestr.len;
    extra_point_len = 1;
  }

  // build command
  // command_prefix = "lookup:all:<key_name>[.namespace]<@sharedby>"
  const size_t commandsize = strlen("lookup:all:")            // lookup:all:
                             + atkey->name.len                // <key_name>
                             + extra_point_len + namespacelen // [.namespace]
                             + atkey->sharedby.len            // <@sharedby>
                             + strlen("\r\n")                 // \r\n
                             + 1;                             // \0
  command = malloc(sizeof(char) * commandsize);
  memset(command, 0, sizeof(char) * commandsize);
  snprintf(command, commandsize, "lookup:all:%.*s%s%.*s%.*s\r\n", (int) atkey->name.len, atkey->name.str,
           extra_point_len == 1 ? "." : "", (int)namespacelen, namespacestr,
           (int)atkey->sharedby.len, atkey->sharedby.str);

  ret = atclient_connection_send(&(atclient->secondary_connection), (unsigned char *)command, commandsize - 1, recv,
                                 recvsize, &recvlen);
  if (ret != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atclient_connection_send: %d\n", ret);
    goto exit;
  }

  if (atclient_stringutils_starts_with(recv, recvlen, "data:", strlen("data:"))) {
    const char *response = recv + 5;

    unsigned char iv[ATCHOPS_IV_BUFFER_SIZE];
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

    atclient_atkey_metadata_from_cjson_node(&(atkey->metadata), metadata);

    // manage IV
    if (atclient_atkey_metadata_is_ivnonce_initialized(&atkey->metadata)) {
      size_t ivlen;
      ret = atchops_base64_decode((unsigned char *)atkey->metadata.ivnonce.str, atkey->metadata.ivnonce.len, iv,
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
  if (root != NULL) {
    cJSON_Delete(root);
  }
  free(command);
  return ret;
}
}