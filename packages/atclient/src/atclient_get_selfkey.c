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
                                                const char *value, const size_t valuesize, const size_t *valuelen);

int atclient_get_selfkey(atclient *atclient, atclient_atkey *atkey, char *value, const size_t valuesize,
                         size_t *valuelen) {
  int ret = 1;

  /*
   * 1. Validate arguments
   */
  if ((ret = atclient_get_selfkey_valid_arguments(atclient, atkey, value, valuesize, valuelen)) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atclient_get_selfkey_valid_arguments: %d\n", ret);
    return ret;
  }

  /*
   * 2. Initialize variables
   */
  char *atkeystr = NULL;

  const size_t recvsize = valuesize;
  unsigned char recv[recvsize];
  memset(recv, 0, sizeof(unsigned char) * recvsize);
  size_t recvlen = 0;

  const size_t selfencryptionkeysize = ATCHOPS_AES_256 / 8; // 32 byte = 256 bits
  unsigned char selfencryptionkey[selfencryptionkeysize];
  memset(selfencryptionkey, 0, sizeof(unsigned char) * selfencryptionkeysize);
  size_t selfencryptionkeylen = 0;

  unsigned char iv[ATCHOPS_IV_BUFFER_SIZE];

  // free later
  cJSON *root = NULL;
  char *cmdbuffer = NULL;
  char *valueraw = NULL;

  /*
   * 3. Build `llookup:` command
   */
  if ((ret = atclient_atkey_to_string(atkey, &atkeystr)) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atclient_atkey_to_string: %d\n", ret);
    goto exit;
  }

  const size_t atkeystrlen = strlen(atkeystr);

  const size_t cmdbuffersize = strlen("llookup:all:\r\n") + atkeystrlen + 1;
  cmdbuffer = (char *)malloc(sizeof(char) * cmdbuffersize);
  if (cmdbuffer == NULL) {
    ret = 1;
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "Failed to allocate memory for cmdbuffer\n");
    goto exit;
  }
  memset(cmdbuffer, 0, sizeof(char) * cmdbuffersize);

  snprintf(cmdbuffer, cmdbuffersize, "llookup:all:%.*s\r\n", (int)atkeystrlen, atkeystr);

  /*
   * 4. Send `llookup:` command
   */
  if ((ret = atclient_connection_send(&(atclient->atserver_connection), (unsigned char *)cmdbuffer, cmdbuffersize - 1,
                                      recv, recvsize, &recvlen)) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atclient_connection_send: %d\n", ret);
    goto exit;
  }

  /*
   * 5. Parse response
   */
  if (!atclient_stringutils_starts_with((char *)recv, "data:")) {
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

  if ((ret = atclient_atkey_metadata_from_jsonstr(&(atkey->metadata), metadatastr)) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atclient_atkey_metadata_from_jsonstr: %d\n", ret);
    goto exit;
  }

  /**
   * 6. Decrypt value
   */

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

  if ((ret = atchops_base64_decode((unsigned char *)atclient->atkeys.selfencryptionkeybase64,
                                   strlen(atclient->atkeys.selfencryptionkeybase64), selfencryptionkey, selfencryptionkeysize,
                                   &selfencryptionkeylen)) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atchops_base64_decode: %d\n", ret);
    goto exit;
  }

  // holds base64 decoded value. Once decoded, it is encrypted cipher text bytes that need to be decrypted
  const size_t valuerawsize = atchops_base64_decoded_size(strlen(data->valuestring));
  valueraw = (char *)malloc(sizeof(char) * valuerawsize);
  if (valueraw == NULL) {
    ret = 1;
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "Failed to allocate memory for valueraw\n");
    goto exit;
  }
  memset(valueraw, 0, sizeof(char) * valuerawsize);
  size_t valuerawlen = 0;

  if ((ret = atchops_base64_decode((unsigned char *)data->valuestring, strlen(data->valuestring),
                                   (unsigned char *)valueraw, valuerawsize, &valuerawlen)) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atchops_base64_decode: %d\n", ret);
    goto exit;
  }

  if ((ret = atchops_aesctr_decrypt(selfencryptionkey, ATCHOPS_AES_256, iv, (unsigned char *)valueraw, valuerawlen,
                                    (unsigned char *)value, valuesize, valuelen)) != 0) {
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
  free(atkeystr);
  return ret;
}
}

static int atclient_get_selfkey_valid_arguments(const atclient *atclient, const atclient_atkey *atkey,
                                                const char *value, const size_t valuesize, const size_t *valuelen) {
  int ret = 1;

  if (atclient == NULL) {
    ret = 1;
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atclient is NULL\n");
    goto exit;
  }

  if (!atclient->_atsign_is_allocated) {
    ret = 1;
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atclient->_atsign_is_allocated is false\n");
    goto exit;
  }

  if (!atclient->_atserver_connection_started) {
    ret = 1;
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atserver connection not started\n");
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

  if (!atclient_atkey_is_sharedby_initialized(atkey)) {
    ret = 1;
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atkey.sharedby is not initialized when it should be\n");
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