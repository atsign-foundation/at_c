#include <atclient/atclient.h>
#include <atclient/stringutils.h>
#include <atlogger/atlogger.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define TAG "atclient_get_atkeys"

static int atclient_get_atkeys_validate_arguments(const atclient *atclient, const char *regex, const bool showhidden,
                                                  const atclient_atkey **atkey, const size_t *output_array_len);

int atclient_get_atkeys(atclient *atclient, const char *regex, const bool showhidden, const size_t recvbuffersize,
                        atclient_atkey **atkey, size_t *output_array_len)

{
  int ret = 1;

  /*
   * 1. Validate arguments
   */
  if ((ret = atclient_get_atkeys_validate_arguments(atclient, regex, showhidden, atkey, output_array_len)) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atclient_get_atkeys_validate_arguments: %d\n", ret);
    return ret;
  }

  if (regex == NULL) {
    regex = "";
  }

  /*
   * 2. Variables
   */
  const size_t scan_cmd_buf_size = strlen("scan") + (showhidden ? strlen(":showHidden:true") : 0) +
                             (strlen(regex) > 0 ? (strlen(" ") + strlen(regex)) : 0) + strlen("\r\n") + 1;
  char scan_cmd[scan_cmd_buf_size];

  unsigned char recv[recvbuffersize];
  size_t recvlen = 0;

  cJSON *root = NULL; // free later

  /*
   * 3. Build scan command
   */
  snprintf(scan_cmd, scan_cmd_buf_size, "scan%s%s%s\r\n", showhidden ? ":showHidden:true" : "", strlen(regex) > 0 ? " " : "",
           regex);

  /*
   * 4. Send scan command
   */
  if ((ret = atclient_connection_send(&(atclient->atserver_connection), (unsigned char *)scan_cmd, scan_cmd_buf_size - 1, recv,
                                      recvbuffersize, &recvlen)) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atclient_connection_send: %d\n", ret);
    goto exit;
  }

  atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_DEBUG, "recv was %lu bytes long\n", recvlen);

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
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "cJSON_Parse failed\n");
    goto exit;
  }

  if (!cJSON_IsArray(root)) {
    ret = 1;
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "root is not an array\n");
    goto exit;
  }

  *output_array_len = cJSON_GetArraySize(root);
  *atkey = malloc(sizeof(atclient_atkey) * (*output_array_len));
  if (*atkey == NULL) {
    ret = 1;
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "malloc failed\n");
    goto exit;
  }

  for (size_t i = 0; i < *output_array_len; i++) {
    atclient_atkey_init(&((*atkey)[i]));
  }

  for (size_t i = 0; i < *output_array_len; i++) {
    cJSON *atkey_json = cJSON_GetArrayItem(root, i);
    if (!cJSON_IsString(atkey_json)) {
      ret = 1;
      atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atkey_json is not a string\n");
      goto atkeys_allocated_error;
    }

    const char *atkey_str = cJSON_GetStringValue(atkey_json);
    if (atkey_str == NULL) {
      ret = 1;
      atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "cJSON_GetStringValue failed\n");
      goto atkeys_allocated_error;
    }

    if ((ret = atclient_atkey_from_string(&(*atkey)[i], atkey_str)) != 0) {
      atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atclient_atkey_from_string failed: %d\n", ret);
      goto atkeys_allocated_error;
    }
  }

  ret = 0;
  goto exit;
atkeys_allocated_error: { // error cleanup
  for (size_t i = 0; i < *output_array_len; i++) {
    atclient_atkey_free(&(*atkey)[i]);
  }
  free(*atkey);
  *atkey = NULL;
  *output_array_len = 0;
}
exit: {
  cJSON_Delete(root);
  return ret;
}
}

static int atclient_get_atkeys_validate_arguments(const atclient *atclient, const char *regex, const bool showhidden,
                                                  const atclient_atkey **atkey, const size_t *output_array_len) {
  int ret = 1;

  // check to make sure null ptr wasn't provided
  if (atkey == NULL || output_array_len == NULL) {
    ret = 1;
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atkey or output_array_len is NULL. These should be pointers\n");
    goto exit;
  }

  // check to make sure atclient is not null
  if (atclient == NULL) {
    ret = 1;
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atclient is NULL\n");
    goto exit;
  }

  if (!atclient_is_atserver_connection_started(atclient)) {
    ret = 1;
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atserver connection not started\n");
    goto exit;
  }

  if (!atclient_is_atsign_initialized(atclient)) {
    ret = 1;
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atsign is not allocated. Make sure to PKAM authenticate first\n");
    goto exit;
  }

  ret = 0;
  goto exit;
exit: { return ret; }
}