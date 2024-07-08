#include <atclient/atclient.h>
#include <atclient/stringutils.h>
#include <atlogger/atlogger.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>

#define TAG "atclient_get_atkeys"

int atclient_get_atkeys(atclient *atclient, const char *regex, const bool showhidden, const size_t recvbuffersize,
                        atclient_atkey **atkey, size_t *output_array_len)

{
  int ret = 1;

  // check to make sure null ptr wasn't provided
  if (atkey == NULL || output_array_len == NULL) {
    ret = 1;
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atkey or output_array_len is NULL. These should be pointers\n");
    return ret;
  }

  // check to make sure atclient is not null
  if(atclient == NULL) {
    ret = 1;
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atclient is NULL\n");
    return ret;
  }

  if(!atclient->_atserver_connection_started) {
    ret = 1;
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atserver connection not started\n");
    return ret;
  }

  if(!atclient->_atsign_is_allocated) {
    ret = 1;
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atsign is not allocated. Make sure to PKAM authenticate first\n");
    return ret;
  }

  if(regex == NULL) {
    regex = "";
  }

  // scan:showHidden:true <regex>
  const size_t scan_command_len = strlen("scan") + (showhidden ? strlen(":showHidden:true") : 0) +
                                  (strlen(regex) > 0 ? (strlen(" ") + strlen(regex)) : 0) + strlen("\r\n") + 1;
  char scan_command[scan_command_len];
  snprintf(scan_command, scan_command_len, "scan%s%s%s\r\n", showhidden ? ":showHidden:true" : "",
           strlen(regex) > 0 ? " " : "", regex);

  const unsigned char recv[recvbuffersize];
  size_t recvlen = 0;

  cJSON *root = NULL;

  // 1. send scan command
  if ((ret = atclient_connection_send(&(atclient->atserver_connection), (unsigned char *)scan_command,
                                      scan_command_len - 1, recv, recvbuffersize, &recvlen)) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atclient_connection_send: %d\n", ret);
    goto exit;
  }

  // log recevied bytes
  atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_DEBUG, "recv was %lu bytes long\n", recvlen);

  // 2. parse response
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
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "cJSON_Parse failed\n");
    goto exit;
  }

  // 3. populate atkey array
  // root looks likes ["atkey1", "atkey2", ...]
  if (!cJSON_IsArray(root)) {
    ret = 1;
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "root is not an array\n");
    goto exit;
  }

  *output_array_len = cJSON_GetArraySize(root);
  *atkey = malloc(sizeof(atclient_atkey) * *output_array_len);
  if (*atkey == NULL) {
    ret = 1;
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "malloc failed\n");
    goto exit;
  }

  for(size_t i = 0; i < *output_array_len; i++) {
    atclient_atkey_init(&(*atkey)[i]);
  }

  for (size_t i = 0; i < *output_array_len; i++) {
    cJSON *atkey_json = cJSON_GetArrayItem(root, i);
    if (!cJSON_IsString(atkey_json)) {
      ret = 1;
      atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atkey_json is not a string\n");
      goto exit1;
    }

    const char *atkey_str = cJSON_GetStringValue(atkey_json);
    if (atkey_str == NULL) {
      ret = 1;
      atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "cJSON_GetStringValue failed\n");
      goto exit1;
    }

    if ((ret = atclient_atkey_from_string(&(*atkey)[i], atkey_str, strlen(atkey_str))) != 0) {
      atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atclient_atkey_from_string failed: %d\n", ret);
      goto exit1;
    }
  }

  ret = 0;
  goto exit;
exit1: {
  for(size_t i = 0; i < *output_array_len; i++) {
    atclient_atkey_free(&(*atkey)[i]);
  }
  free(*atkey);
  *atkey = NULL;
  *output_array_len = 0;
}
exit: { return ret; }
}