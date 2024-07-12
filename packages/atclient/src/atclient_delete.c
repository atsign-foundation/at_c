#include "atclient/atclient.h"
#include "atclient/atkey.h"
#include "atclient/atstr.h"
#include "atclient/constants.h"
#include "atclient/stringutils.h"
#include "atlogger/atlogger.h"
#include <stdlib.h>
#include <string.h>

#define TAG "atclient_delete"

int atclient_delete(atclient *atclient, const atclient_atkey *atkey) {
  int ret = 1;

  size_t pos = 0;

  const size_t cmdbuffersize = strlen("delete:") + ATCLIENT_ATKEY_FULL_LEN + strlen("\r\n") + 1;
  char cmdbuffer[cmdbuffersize];
  memset(cmdbuffer, 0, sizeof(char) * (cmdbuffersize));

  char *atkeystr = NULL;
  size_t atkeystrlen = 0;

  const size_t recvsize = 4096;
  unsigned char *recv;
  if (!atclient->async_read) {
    recv = malloc(sizeof(unsigned char) * recvsize);
    memset(recv, 0, sizeof(unsigned char) * recvsize);
  }
  size_t recvlen = 0;

  snprintf(cmdbuffer + pos, cmdbuffersize - pos, "delete:");
  pos += strlen("delete:");

  ret = atclient_atkey_to_string(atkey, &atkeystr);
  if (ret != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atclient_atkey_to_string: %d\n", ret);
    goto exit;
  }
  atkeystrlen = strlen(atkeystr);

  snprintf(cmdbuffer + pos, cmdbuffersize - pos, "%.*s\r\n", (int)atkeystrlen, atkeystr);

  ret = atclient_connection_send(&(atclient->atserver_connection), (unsigned char *)cmdbuffer, cmdbuffersize - 1, recv,
                                 recvsize, &recvlen);
  if (ret != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atclient_connection_send: %d\n", ret);
    goto exit;
  } else if (atclient->async_read) {
    goto exit;
  }

  if (!atclient_stringutils_starts_with((char *)recv, recvlen, "data:", 5)) {
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
  return ret;
}
}
