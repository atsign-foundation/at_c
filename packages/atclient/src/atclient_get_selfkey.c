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

int atclient_get_selfkey(atclient *atclient, atclient_atkey *atkey, char *value, const size_t valuelen,
                         size_t *valueolen) {
  if (atkey->atkeytype != ATCLIENT_ATKEY_TYPE_SELFKEY) {
    atclient_atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atkey->atkeytype != ATKEYTYPE_SELF\n");
    return 1;
  }

  int ret = 1;

  // 1. initialize variables
  const size_t atkeystrlen = ATCLIENT_ATKEY_FULL_LEN;
  char atkeystr[atkeystrlen];
  memset(atkeystr, 0, sizeof(char) * atkeystrlen);
  size_t atkeystrolen = 0;

  const size_t recvlen = 4096;
  unsigned char recv[recvlen];
  memset(recv, 0, sizeof(unsigned char) * recvlen);
  size_t recvolen = 0;

  unsigned char iv[ATCHOPS_IV_BUFFER_SIZE];

  cJSON *root = NULL;
  char *cmdbuffer = NULL;

  // 2. build llookup: command
  ret = atclient_atkey_to_string(atkey, atkeystr, atkeystrlen, &atkeystrolen);

  if (ret != 0) {
    atclient_atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atclient_atkey_to_string: %d\n", ret);
    goto exit;
  }

  const size_t cmdbufferlen = strlen("llookup:all:\r\n") + atkeystrolen + 1;
  cmdbuffer = malloc(sizeof(char) * cmdbufferlen);
  memset(cmdbuffer, 0, cmdbufferlen);

  snprintf(cmdbuffer, cmdbufferlen, "llookup:all:%.*s\r\n", (int)atkeystrolen, atkeystr);

  // 3. send llookup: command
  ret = atclient_connection_send(&(atclient->secondary_connection), (unsigned char *)cmdbuffer, cmdbufferlen - 1, recv,
                                 recvlen, &recvolen);
  if (ret != 0) {
    atclient_atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atclient_connection_send: %d\n", ret);
    goto exit;
  }

  // 4. parse response
  if (!atclient_stringutils_starts_with((char *)recv, recvolen, "data:", 5)) {
    ret = 1;
    atclient_atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "recv was \"%.*s\" and did not have prefix \"data:\"\n",
                          (int)recvolen, recv);
    goto exit;
  }

  char *recvwithoutdata = (char *)recv + 5;

  root = cJSON_Parse(recvwithoutdata);
  if (root == NULL) {
    ret = 1;
    atclient_atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "cJSON_Parse: %d\n", ret);
    goto exit;
  }

  cJSON *metadata = cJSON_GetObjectItem(root, "metaData");
  if (metadata == NULL) {
    ret = 1;
    atclient_atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "cJSON_GetObjectItem: %d\n", ret);
    goto exit;
  }

  char *metadatastr = cJSON_Print(metadata);

  ret = atclient_atkey_metadata_from_jsonstr(&(atkey->metadata), metadatastr, strlen(metadatastr));
  if (ret != 0) {
    atclient_atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atclient_atkey_metadata_from_jsonstr: %d\n", ret);
    goto exit;
  }

  if (atclient_atkey_metadata_is_ivnonce_initialized(&atkey->metadata)) {
    size_t ivolen;
    ret = atchops_base64_decode((unsigned char *)atkey->metadata.ivnonce.str, atkey->metadata.ivnonce.olen, iv,
                                ATCHOPS_IV_BUFFER_SIZE, &ivolen);
    if (ret != 0) {
      atclient_atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atchops_base64_decode: %d\n", ret);
      goto exit;
    }

    if (ivolen != ATCHOPS_IV_BUFFER_SIZE) {
      ret = 1;
      atclient_atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "ivolen != ivlen (%d != %d)\n", ivolen,
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
    atclient_atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "cJSON_GetObjectItem: %d\n", ret);
    goto exit;
  }

  const size_t selfencryptionkeysize = ATCHOPS_AES_256 / 8;
  unsigned char selfencryptionkey[selfencryptionkeysize];
  memset(selfencryptionkey, 0, sizeof(unsigned char) * selfencryptionkeysize);
  size_t selfencryptionkeylen = 0;

  ret = atchops_base64_decode(atclient->atkeys.selfencryptionkeystr.str, atclient->atkeys.selfencryptionkeystr.olen,
                              selfencryptionkey, selfencryptionkeysize, &selfencryptionkeylen);

  ret = atchops_aesctr_decrypt(selfencryptionkey, ATCHOPS_AES_256, iv, (unsigned char *)data->valuestring,
                               strlen(data->valuestring), (unsigned char *)value, valuelen, valueolen);
  if (ret != 0) {
    atclient_atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atchops_aesctr_decrypt: %d\n", ret);
    goto exit;
  }

  ret = 0;
  goto exit;
exit: { return ret; }
}