#include "atclient/atclient.h"
#include "atclient/atkey.h"
#include "atclient/constants.h"
#include "atclient/stringutils.h"
#include <atlogger/atlogger.h>
#include <stdlib.h>
#include <string.h>

#define TAG "atclient_get_publickey"

int atclient_get_publickey(atclient *atclient, atclient_atkey *atkey, char *value, const size_t valuesize,
                           size_t *valuelen, bool bypasscache) {
  if (atclient->async_read) {
    atlogger_log(
        TAG, ATLOGGER_LOGGING_LEVEL_ERROR,
        "atclient_get_publickey cannot be called from an async_read atclient, it will cause a race condition\n");
    return 1;
  }
  int ret = 1;

  if (atkey->atkeytype != ATCLIENT_ATKEY_TYPE_PUBLICKEY) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atkey->atkeytype != ATKEYTYPE_PUBLIC\n");
    return 1;
  }

  // 1. initialize variables
  const size_t atkeystrlen = ATCLIENT_ATKEY_FULL_LEN;
  atclient_atstr atkeystr;
  atclient_atstr_init(&atkeystr, atkeystrlen);

  const size_t recvsize = valuesize;
  unsigned char recv[recvsize];
  memset(recv, 0, sizeof(unsigned char) * recvsize);
  size_t recvlen = 0;

  cJSON *root = NULL;
  char *cmdbuffer = NULL;
  char *metadatastr = NULL;

  // 2. build plookup: command
  ret = atclient_atkey_to_string(atkey, atkeystr.str, atkeystr.size, &atkeystr.len);
  if (ret != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atclient_atkey_to_string: %d\n", ret);
    goto exit;
  }

  char *bypasscachestr = NULL;
  if (bypasscache) {
    bypasscachestr = "bypassCache:true:";
  }

  char *atkeystrwithoutpublic = NULL;
  char *ptr = strstr(atkeystr.str, "public:");
  if (ptr != NULL) {
    atkeystrwithoutpublic = ptr + strlen("public:");
  } else {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "Could not find \"public:\" from string \"%s\"\n", atkeystr.str);
    goto exit;
  }

  const size_t cmdbuffersize = strlen("plookup:all:\r\n") + (bypasscachestr != NULL ? strlen(bypasscachestr) : 0) +
                               strlen(atkeystrwithoutpublic) + 1;
  cmdbuffer = malloc(sizeof(char) * cmdbuffersize);
  memset(cmdbuffer, 0, cmdbuffersize);
  snprintf(cmdbuffer, cmdbuffersize, "plookup:%sall:%s\r\n", bypasscachestr != NULL ? bypasscachestr : "",
           atkeystrwithoutpublic);
  const size_t cmdbufferlen = strlen(cmdbuffer);

  // 3. send plookup: command
  ret = atclient_connection_send(&(atclient->atserver_connection), (unsigned char *)cmdbuffer, cmdbufferlen, recv,
                                 recvsize, &recvlen);
  if (ret != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atclient_connection_send: %d\n", ret);
    goto exit;
  }

  // 4. parse response

  // 4a. if recv does not start with "data:", we probably got an error
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

  // 4b. set *value and *valuelen
  cJSON *data = cJSON_GetObjectItem(root, "data");
  if (data == NULL) {
    ret = 1;
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "cJSON_GetObjectItem: %d\n", ret);
    goto exit;
  }

  memset(value, 0, valuesize);
  memcpy(value, data->valuestring, strlen(data->valuestring));
  *valuelen = strlen(value);

  // 4c. write to atkey->metadata
  cJSON *metadata = cJSON_GetObjectItem(root, "metaData");
  if (metadata == NULL) {
    ret = 1;
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "cJSON_GetObjectItem: %d\n", ret);
    goto exit;
  }

  metadatastr = cJSON_Print(metadata);

  ret = atclient_atkey_metadata_from_jsonstr(&(atkey->metadata), metadatastr, strlen(metadatastr));
  if (ret != 0) {
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
  return ret;
}
}
