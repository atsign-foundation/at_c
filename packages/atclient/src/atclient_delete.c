#include "atclient/atclient.h"
#include "atclient/atkey.h"
#include "atclient/constants.h"
#include "atclient/stringutils.h"
#include "atlogger/atlogger.h"
#include <stdlib.h>
#include <string.h>

#define TAG "atclient_delete"

static int atclient_delete_validate_arguments(const atclient *atclient, const atclient_atkey *atkey);

int atclient_delete(atclient *atclient, const atclient_atkey *atkey, int *commit_id) {
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
  char *cmdbuffer = NULL;
  char *atkeystr = NULL;

  const size_t recvsize = 256; // sufficient buffer size to receive response containing commit id
  unsigned char *recv = NULL;
  if (!atclient->async_read) {
    recv = malloc(sizeof(unsigned char) * recvsize);
    if (recv == NULL) {
      ret = 1;
      atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "Failed to allocate memory for recv\n");
      goto exit;
    }
    memset(recv, 0, sizeof(unsigned char) * recvsize);
  }
  size_t recvlen = 0;

  /*
   * 3. Build delete command
   */

  if ((ret = atclient_atkey_to_string(atkey, &atkeystr)) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atclient_atkey_to_string: %d\n", ret);
    goto exit;
  }
  const size_t atkeystrlen = strlen(atkeystr);

  const size_t cmdbuffersize = strlen("delete:") + atkeystrlen + strlen("\r\n") + 1;
  cmdbuffer = malloc(sizeof(char) * cmdbuffersize);
  if (cmdbuffer == NULL) {
    ret = 1;
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "Failed to allocate memory for cmdbuffer\n");
    goto exit;
  }
  snprintf(cmdbuffer, cmdbuffersize, "delete:%s\r\n", atkeystr);

  /*
   * 4. Send command
   */
  if ((ret = atclient_connection_send(&(atclient->atserver_connection), (unsigned char *)cmdbuffer, cmdbuffersize - 1,
                                      recv, recvsize, &recvlen)) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atclient_connection_send: %d\n", ret);
    goto exit;
  }

  if (atclient->async_read) {
    goto exit;
  }

  char *respose = (char *)recv;

  if (!atclient_stringutils_starts_with(respose, "data:")) {
    ret = 1;
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "recv was \"%.*s\" and did not have prefix \"data:\"\n",
                 (int)recvlen, recv);
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
  free(atkeystr);
  free(cmdbuffer);
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

  if (!atclient_atkey_is_sharedby_initialized(atkey)) {
    ret = 1;
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atclient_atkey_is_sharedby_initialized is false\n");
    goto exit;
  }

  ret = 0;
  goto exit;
exit: { return ret; }
}