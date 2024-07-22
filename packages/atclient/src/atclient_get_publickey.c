#include "atclient/atclient.h"
#include "atclient/atkey.h"
#include "atclient/constants.h"
#include "atclient/stringutils.h"
#include <atlogger/atlogger.h>
#include <stdlib.h>
#include <string.h>

#define TAG "atclient_get_publickey"

static int atclient_get_publickey_validate_arguments(atclient *atclient, atclient_atkey *atkey, char *value,
                                                     const size_t valuesize, size_t *valuelen, bool bypasscache);

int atclient_get_publickey(atclient *atclient, atclient_atkey *atkey, char *value, const size_t valuesize,
                           size_t *valuelen, bool bypasscache) {
  int ret = 1;

  /*
   * 1. Validate arguments
   */
  if ((ret = atclient_get_publickey_validate_arguments(atclient, atkey, value, valuesize, valuelen, bypasscache)) !=
      0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atclient_get_publickey_validate_arguments: %d\n", ret);
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

  cJSON *root = NULL;
  char *cmdbuffer = NULL;
  char *metadatastr = NULL;

  /*
   * 3. Build `plookup:` command
   */
  if ((ret = atclient_atkey_to_string(atkey, &atkeystr)) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atclient_atkey_to_string: %d\n", ret);
    goto exit;
  }

  char *atkeystrwithoutpublic = NULL;
  char *ptr = strstr(atkeystr, "public:");
  if (ptr != NULL) {
    atkeystrwithoutpublic = ptr + strlen("public:");
  } else {
    ret = 1;
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "Could not find \"public:\" from string \"%s\"\n", atkeystr);
    goto exit;
  }

  const size_t cmdbuffersize = strlen("plookup:all:\r\n") + (bypasscache ? strlen("bypassCache:true:") : 0) +
                               strlen(atkeystrwithoutpublic) + 1;
  cmdbuffer = malloc(sizeof(char) * cmdbuffersize);
  if (cmdbuffer == NULL) {
    ret = 1;
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "Failed to allocate memory for cmdbuffer\n");
    goto exit;
  }
  memset(cmdbuffer, 0, cmdbuffersize);
  snprintf(cmdbuffer, cmdbuffersize, "plookup:%sall:%s\r\n", bypasscache ? "bypassCache:true:" : "",
           atkeystrwithoutpublic);
  const size_t cmdbufferlen = strlen(cmdbuffer);

  /*
   * 4. Send `plookup:` command
   */
  ret = atclient_connection_send(&(atclient->atserver_connection), (unsigned char *)cmdbuffer, cmdbufferlen, recv,
                                 recvsize, &recvlen);
  if (ret != 0) {
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

  cJSON *data = cJSON_GetObjectItem(root, "data");
  if (data == NULL) {
    ret = 1;
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "cJSON_GetObjectItem: %d\n", ret);
    goto exit;
  }

  /*
   * 6. Return data to caller
   */
  memcpy(value, data->valuestring, strlen(data->valuestring));
  *valuelen = strlen(value);

  // 6b. write to atkey->metadata
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

  ret = 0;
  goto exit;
exit: {
  if (root != NULL) {
    cJSON_Delete(root);
  }
  free(metadatastr);
  free(cmdbuffer);
  free(atkeystr);
  return ret;
}
}

static int atclient_get_publickey_validate_arguments(atclient *atclient, atclient_atkey *atkey, char *value,
                                                     const size_t valuesize, size_t *valuelen, bool bypasscache) {
  int ret = 1;

  if (atclient == NULL) {
    ret = 1;
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atclient is NULL\n");
    goto exit;
  }

  if (atkey == NULL) {
    ret = 1;
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atkey is NULL\n");
    goto exit;
  }

  const atclient_atkey_type atkey_type = atclient_atkey_get_type(atkey);

  if (atkey_type != ATCLIENT_ATKEY_TYPE_PUBLICKEY) {
    ret = 1;
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atkey is not a public key\n");
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

  if(!atclient_is_atserver_connection_started(atclient)) {
    ret = 1;
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atserver connection not started\n");
    goto exit;
  }

  if(!atclient_is_atsign_initialized(atclient)) {
    ret = 1;
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atsign not initialized\n");
    goto exit;
  }

  ret = 0;
  goto exit;
exit: { return ret; }
}