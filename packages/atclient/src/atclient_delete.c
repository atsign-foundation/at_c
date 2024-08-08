#include "atclient/atclient.h"
#include "atclient/atkey.h"
#include "atclient/constants.h"
#include "atclient/string_utils.h"
#include "atlogger/atlogger.h"
#include <stdlib.h>
#include <atclient/request_options.h>
#include <string.h>

#define TAG "atclient_delete"

static int atclient_delete_validate_arguments(const atclient *atclient, const atclient_atkey *atkey);

int atclient_delete(atclient *atclient, const atclient_atkey *atkey, const atclient_delete_request_options *options, int *commit_id) {
  int ret = 1;

  /*
   * 1. Check arguments
   */
  if ((ret = atclient_delete_validate_arguments(atclient, atkey)) != 0) {
    ret = 1;
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atclient_delete_validate_arguments: %d\n", ret);
    return ret;
  }

  /*
   * 2. Initialize variables
   */
  char *delete_cmd = NULL;
  char *atkey_str = NULL;

  const size_t recv_size = 256; // sufficient buffer size to receive response containing commit id
  unsigned char *recv = NULL;
  if (!atclient->async_read) {
    recv = malloc(sizeof(unsigned char) * recv_size);
    if (recv == NULL) {
      ret = 1;
      atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "Failed to allocate memory for recv\n");
      goto exit;
    }
    memset(recv, 0, sizeof(unsigned char) * recv_size);
  }
  size_t recv_len = 0;

  /*
   * 3. Build delete command
   */

  if ((ret = atclient_atkey_to_string(atkey, &atkey_str)) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atclient_atkey_to_string: %d\n", ret);
    goto exit;
  }
  const size_t atkey_strlen = strlen(atkey_str);

  const size_t delete_cmd_size = strlen("delete:") + atkey_strlen + strlen("\r\n") + 1;
  delete_cmd = malloc(sizeof(char) * delete_cmd_size);
  if (delete_cmd == NULL) {
    ret = 1;
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "Failed to allocate memory for delete_cmd\n");
    goto exit;
  }
  snprintf(delete_cmd, delete_cmd_size, "delete:%s\r\n", atkey_str);

  /*
   * 4. Send command
   */
  if ((ret = atclient_connection_send(&(atclient->atserver_connection), (unsigned char *)delete_cmd, delete_cmd_size - 1,
                                      recv, recv_size, &recv_len)) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atclient_connection_send: %d\n", ret);
    goto exit;
  }

  if (atclient->async_read) {
    goto exit;
  }

  char *respose = (char *)recv;

  if (!atclient_string_utils_starts_with(respose, "data:")) {
    ret = 1;
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "recv was \"%.*s\" and did not have prefix \"data:\"\n",
                 (int)recv_len, recv);
    goto exit;
  }

  char *response_without_data = respose + strlen("data:");

  if(commit_id != NULL) {
    *commit_id = atoi(response_without_data);
  }

  ret = 0;
  goto exit;
exit: {
  free(recv);
  free(atkey_str);
  free(delete_cmd);
  return ret;
}
}

static int atclient_delete_validate_arguments(const atclient *atclient, const atclient_atkey *atkey) {
  int ret = 1;

  if (atclient == NULL) {
    ret = 1;
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atclient is NULL\n");
    goto exit;
  }

  if (!atclient_is_atsign_initialized(atclient)) {
    ret = 1;
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atserver_connection is not connected\n");
    goto exit;
  }

  if (!atclient_is_atserver_connection_started(atclient)) {
    ret = 1;
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atserver_connection is not started\n");
    goto exit;
  }

  if (atkey == NULL) {
    ret = 1;
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atkey is NULL\n");
    goto exit;
  }

  if (!atclient_atkey_is_key_initialized(atkey)) {
    ret = 1;
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atclient_atkey_is_key_initialized is false\n");
    goto exit;
  }

  if (!atclient_atkey_is_shared_by_initialized(atkey)) {
    ret = 1;
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atclient_atkey_is_shared_by_initialized is false\n");
    goto exit;
  }

  ret = 0;
  goto exit;
exit: { return ret; }
}