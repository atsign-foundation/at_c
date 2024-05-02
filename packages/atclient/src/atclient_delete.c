#include "atclient/atclient.h"
#include "atclient/atkey.h"
#include <stdlib.h>
#include <string.h>
#include "atclient/atstr.h"
#include "atclient/constants.h"
#include "atclient/stringutils.h"
#include "atlogger/atlogger.h"

#define TAG "atclient_delete"

int atclient_delete(atclient *atclient, const atclient_atkey *atkey) {
  int ret = 1;

  atclient_atstr cmdbuffer;
  atclient_atstr_init_literal(&cmdbuffer, ATCLIENT_ATKEY_FULL_LEN + strlen("delete:"), "delete:");

  char atkeystr[ATCLIENT_ATKEY_FULL_LEN];
  memset(atkeystr, 0, sizeof(char) * ATCLIENT_ATKEY_FULL_LEN);
  size_t atkeystrolen = 0;

  unsigned char recv[4096] = {0};
  size_t recvolen = 0;

  ret = atclient_atkey_to_string(atkey, atkeystr, ATCLIENT_ATKEY_FULL_LEN, &atkeystrolen);
  if (ret != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atclient_atkey_to_string: %d\n", ret);
    goto exit;
  }

  ret = atclient_atstr_append(&cmdbuffer, "%.*s\n", (int)atkeystrolen, atkeystr);
  if (ret != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atclient_atstr_append: %d\n", ret);
    goto exit;
  }

  ret = atclient_connection_send(&(atclient->secondary_connection), (unsigned char *)cmdbuffer.str, cmdbuffer.olen,
                                 recv, 4096, &recvolen);
  if (ret != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atclient_connection_send: %d\n", ret);
    goto exit;
  }

  if (!atclient_stringutils_starts_with((char *)recv, recvolen, "data:", 5)) {
    ret = 1;
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "recv was \"%.*s\" and did not have prefix \"data:\"\n",
                          (int)recvolen, recv);
    goto exit;
  }

  ret = 0;
  goto exit;
exit: {
  atclient_atstr_free(&cmdbuffer);
  return ret;
}
}
