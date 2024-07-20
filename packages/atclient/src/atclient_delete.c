#include "atclient/atclient.h"
#include "atclient/atkey.h"
#include "atclient/constants.h"
#include "atclient/stringutils.h"
#include "atlogger/atlogger.h"
#include <stdlib.h>
#include <string.h>

#define TAG "atclient_delete"

static int atclient_delete_validate_arguments(atclient *atclient, const atclient_atkey *atkey);

int atclient_delete(atclient *atclient, const atclient_atkey *atkey) {
  int ret = 1;

  /*
   * 1. Check arguments
   */
  if ((ret = atclient_delete_validate_arguments(atclient, atkey)) != 0) {
    ret = 1;
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atclient_delete_validate_arguments: %d\n", ret);
    goto exit;
  }

  /*
   * 2. Initialize variables
   */
  size_t cmdbuffersize;
  char *cmdbuffer = NULL; // free later

  char *atkeystr = NULL; // free later
  size_t atkeystrlen = 0;

  const size_t recvsize = 4096;
  unsigned char *recv;
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
  atkeystrlen = strlen(atkeystr);

  cmdbuffersize = strlen("delete:") + atkeystrlen + strlen("\r\n") + 1;
  cmdbuffer = malloc(sizeof(char) * cmdbuffersize);
  if (cmdbuffer == NULL) {
    ret = 1;
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "Failed to allocate memory for cmdbuffer\n");
    goto exit;
  }
  snprintf(cmdbuffer, cmdbuffersize, "delete:%.*s\r\n", (int)atkeystrlen, atkeystr);

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

  if (!atclient_stringutils_starts_with((char *)recv, "data:")) {
    ret = 1;
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "recv was \"%.*s\" and did not have prefix \"data:\"\n",
                 (int)recvlen, recv);
    goto exit;
  }

  ret = 0;
  goto exit;
exit: {
  if (!atclient->async_read) {
    free(recv);
  }
  free(atkeystr);
  free(cmdbuffer);
  return ret;
}
}

static int atclient_delete_validate_arguments(atclient *atclient, const atclient_atkey *atkey) {
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

  // TODO use a function in atclient_atkey to check if atkey is complete

  ret = 0;
  goto exit;
exit: { return ret; }
}