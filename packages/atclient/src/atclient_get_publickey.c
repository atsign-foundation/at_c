#include <atlogger/atlogger.h>
#include "atclient/atclient.h"
#include "atclient/atkey.h"
#include "atclient/atbytes.h"
#include "atclient/constants.h"
#include "atclient/stringutils.h"
#include <stdlib.h>
#include <string.h>

#define TAG "atclient_get_publickey"

int atclient_get_publickey(atclient *atclient, atclient_connection *root_conn, atclient_atkey *atkey, char *value,
                           const size_t valuelen, size_t *valueolen, bool bypasscache) {
  int ret = 1;

  if (atkey->atkeytype != ATCLIENT_ATKEY_TYPE_PUBLICKEY) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atkey->atkeytype != ATKEYTYPE_PUBLIC\n");
    return 1;
  }

  // 1. initialize variables
  const size_t atkeystrlen = ATCLIENT_ATKEY_FULL_LEN;
  atclient_atstr atkeystr;
  atclient_atstr_init(&atkeystr, atkeystrlen);

  const size_t recvlen = 4096;
  atclient_atbytes recv;
  atclient_atbytes_init(&recv, recvlen);

  cJSON *root = NULL;
  char *cmdbuffer = NULL;
  char *metadatastr = NULL;

  // 2. build plookup: command
  ret = atclient_atkey_to_string(atkey, atkeystr.str, atkeystr.len, &atkeystr.olen);
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
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "Could not find \"public:\" from string \"%s\"\n",
                          atkeystr.str);
    goto exit;
  }

  const size_t cmdbufferlen = strlen("plookup:all:\r\n") + (bypasscachestr != NULL ? strlen(bypasscachestr) : 0) +
                              strlen(atkeystrwithoutpublic) + 1;
  cmdbuffer = malloc(sizeof(char) * cmdbufferlen);
  memset(cmdbuffer, 0, cmdbufferlen);
  snprintf(cmdbuffer, cmdbufferlen, "plookup:%sall:%s\r\n", bypasscachestr != NULL ? bypasscachestr : "",
           atkeystrwithoutpublic);
  const size_t cmdbufferolen = strlen(cmdbuffer);

  // 3. send plookup: command
  ret = atclient_connection_send(&(atclient->secondary_connection), (unsigned char *)cmdbuffer, cmdbufferolen,
                                 recv.bytes, recv.len, &recv.olen);
  if (ret != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atclient_connection_send: %d\n", ret);
    goto exit;
  }

  // 4. parse response

  // 4a. if recv does not start with "data:", we probably got an error
  if (!atclient_stringutils_starts_with((char *)recv.bytes, recv.olen, "data:", 5)) {
    ret = 1;
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "recv was \"%.*s\" and did not have prefix \"data:\"\n",
                          (int)recv.olen, recv.bytes);
    goto exit;
  }

  char *recvwithoutdata = (char *)recv.bytes + 5;

  root = cJSON_Parse(recvwithoutdata);
  if (root == NULL) {
    ret = 1;
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "cJSON_Parse: %d\n", ret);
    goto exit;
  }

  // 4b. set *value and *valueolen
  cJSON *data = cJSON_GetObjectItem(root, "data");
  if (data == NULL) {
    ret = 1;
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "cJSON_GetObjectItem: %d\n", ret);
    goto exit;
  }

  memset(value, 0, valuelen);
  memcpy(value, data->valuestring, strlen(data->valuestring));
  *valueolen = strlen(value);

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
