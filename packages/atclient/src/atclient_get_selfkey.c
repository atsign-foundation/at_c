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

int atclient_get_selfkey(atclient *atclient, atclient_atkey *atkey, char *value, const size_t valuesize,
                         size_t *valuelen) {
  if (atclient->async_read) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR,
                 "atclient_get_selfkey cannot be called from an async_read atclient, it will cause a race condition\n");
    return 1;
  }
  if (atkey->atkeytype != ATCLIENT_ATKEY_TYPE_SELFKEY) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atkey->atkeytype != ATKEYTYPE_SELF\n");
    return 1;
  }

  int ret = 1;

  // 1. initialize variables
  const size_t atkeystrsize = ATCLIENT_ATKEY_FULL_LEN;
  char atkeystr[atkeystrsize];
  memset(atkeystr, 0, sizeof(char) * atkeystrsize);
  size_t atkeystrlen = 0;

  const size_t recvsize = 4096;
  unsigned char recv[recvsize];
  memset(recv, 0, sizeof(unsigned char) * recvsize);
  size_t recvlen = 0;

  const size_t selfencryptionkeysize = ATCHOPS_AES_256 / 8;
  unsigned char selfencryptionkey[selfencryptionkeysize];
  memset(selfencryptionkey, 0, sizeof(unsigned char) * selfencryptionkeysize);
  size_t selfencryptionkeylen = 0;

  unsigned char iv[ATCHOPS_IV_BUFFER_SIZE];

  cJSON *root = NULL;
  char *cmdbuffer = NULL;
  char *valueraw = NULL;

  // 2. build llookup: command
  ret = atclient_atkey_to_string(atkey, atkeystr, atkeystrsize, &atkeystrlen);

  if (ret != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atclient_atkey_to_string: %d\n", ret);
    goto exit;
  }

  const size_t cmdbuffersize = strlen("llookup:all:\r\n") + atkeystrlen + 1;
  cmdbuffer = (char *)malloc(sizeof(char) * cmdbuffersize);
  memset(cmdbuffer, 0, sizeof(char) * cmdbuffersize);

  snprintf(cmdbuffer, cmdbuffersize, "llookup:all:%.*s\r\n", (int)atkeystrlen, atkeystr);

  // 3. send llookup: command
  ret = atclient_connection_send(&(atclient->atserver_connection), (unsigned char *)cmdbuffer, cmdbuffersize - 1, recv,
                                 recvsize, &recvlen);
  if (ret != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atclient_connection_send: %d\n", ret);
    goto exit;
  }

  // 4. parse response
  if (!atclient_stringutils_starts_with((char *)recv, recvlen, "data:", 5)) {
    ret = 1;
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "recv was \"%.*s\" and did not have prefix \"data:\"\n",
                 (int)recvlen, recv);
    goto exit;
  }

  char *recvwithoutdata = (char *)recv + 5;

  root = cJSON_Parse(recvwithoutdata);
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

  ret = atchops_base64_decode((unsigned char *)atclient->atkeys.selfencryptionkeystr.str,
                              atclient->atkeys.selfencryptionkeystr.len, selfencryptionkey, selfencryptionkeysize,
                              &selfencryptionkeylen);
  if (ret != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atchops_base64_decode: %d\n", ret);
    goto exit;
  }

  const size_t valuerawsize = strlen(data->valuestring) * 8;
  valueraw = (char *)malloc(sizeof(char) * valuerawsize);
  memset(valueraw, 0, sizeof(char) * valuerawsize);
  size_t valuerawlen = 0;

  ret = atchops_base64_decode((unsigned char *)data->valuestring, strlen(data->valuestring), (unsigned char *)valueraw,
                              valuerawsize, &valuerawlen);
  if (ret != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atchops_base64_decode: %d\n", ret);
    goto exit;
  }

  ret = atchops_aesctr_decrypt(selfencryptionkey, ATCHOPS_AES_256, iv, (unsigned char *)valueraw, valuerawlen,
                               (unsigned char *)value, valuesize, valuelen);
  if (ret != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atchops_aesctr_decrypt: %d\n", ret);
    goto exit;
  }

  ret = 0;
  goto exit;

exit: {
  if (root != NULL) {
    cJSON_Delete(root);
  }
  free(valueraw);
  free(cmdbuffer);
  return ret;
}
}
