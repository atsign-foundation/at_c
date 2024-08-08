#include <atclient/atclient.h>
#include <atclient/string_utils.h>
#include <atlogger/atlogger.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define TAG "atclient_get_atkeys"

static int atclient_get_atkeys_validate_arguments(const atclient *atclient, const atclient_atkey **atkey, const size_t *output_array_len);

int atclient_get_atkeys(atclient *atclient, atclient_atkey **atkey, size_t *output_array_len, const atclient_get_atkeys_request_options *request_options) {
  int ret = 1;

  /*
   * 1. Validate arguments
   */
  if ((ret = atclient_get_atkeys_validate_arguments(atclient, (const atclient_atkey **) atkey, output_array_len)) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atclient_get_atkeys_validate_arguments: %d\n", ret);
    return ret;
  }

  /*
   * 2. Variables
   */
  size_t scan_cmd_size = strlen("scan");

  if(request_options != NULL) {
    if(atclient_get_atkeys_request_options_is_show_hidden_initialized(request_options)) {
      if(request_options->show_hidden) {
        scan_cmd_size += strlen(":showHidden:true");
      } else {
        scan_cmd_size += strlen(":showHidden:false");
      }
    }
    if(atclient_get_atkeys_request_options_is_regex_initialized(request_options)) {
      scan_cmd_size += strlen(" ") + strlen(request_options->regex);
    }
  }

  scan_cmd_size += strlen("\r\n") + 1;


  char scan_cmd[scan_cmd_size];

  const size_t recv_size = 8192; // TODO change using atclient_connection_read which will handle realloc
  unsigned char recv[recv_size];
  size_t recv_len = 0;

  cJSON *root = NULL; // free later

  /*
   * 3. Build scan command
   */
  size_t pos = 0;
  pos += snprintf(scan_cmd + pos, scan_cmd_size - pos, "scan");
  if(request_options != NULL) {
    if(atclient_get_atkeys_request_options_is_show_hidden_initialized(request_options)) {
      if(request_options->show_hidden) {
        pos += snprintf(scan_cmd + pos, scan_cmd_size - pos, ":showHidden:true");
      } else {
        pos += snprintf(scan_cmd + pos, scan_cmd_size - pos, ":showHidden:false");
      }
    }
    if(atclient_get_atkeys_request_options_is_regex_initialized(request_options)) {
      pos += snprintf(scan_cmd + pos, scan_cmd_size - pos, " %s", request_options->regex);
    }
  }
  pos += snprintf(scan_cmd + pos, scan_cmd_size - pos, "\r\n");

  const size_t scan_cmd_len = pos;

  /*
   * 4. Send scan command
   */
  if ((ret = atclient_connection_send(&(atclient->atserver_connection), (unsigned char *)scan_cmd, scan_cmd_len, recv,
                                      recv_size, &recv_len)) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atclient_connection_send: %d\n", ret);
    goto exit;
  }

  atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_DEBUG, "recv was %lu bytes long\n", recv_len);

  /*
   * 5. Parse response
   */
  if (!atclient_string_utils_starts_with((char *)recv, "data:")) {
    ret = 1;
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "recv was \"%.*s\" and did not have prefix \"data:\"\n",
                 (int)recv_len, recv);
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

static int atclient_get_atkeys_validate_arguments(const atclient *atclient, const atclient_atkey **atkey, const size_t *output_array_len) {
  int ret = 1;

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

  if(atkey == NULL) {
    ret = 1;
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atkey is NULL\n");
    goto exit;
  }

  if(output_array_len == NULL) {
    ret = 1;
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "output_array_len is NULL\n");
    goto exit;
  }

  ret = 0;
  goto exit;
exit: { return ret; }
}