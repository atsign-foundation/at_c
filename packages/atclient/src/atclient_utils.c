#include "atclient/atclient_utils.h"
#include "atclient/atkeys.h"
#include "atclient/connection.h"
#include "atclient/stringutils.h"
#include <atlogger/atlogger.h>
#include <stddef.h>
#include <stdlib.h>
#include <pwd.h>
#include <unistd.h>
#include <string.h>

#define TAG "atclient_utils"

int atclient_utils_find_atserver_address(const char *atdirectory_host, const int atdirectory_port, const char *atsign,
                                   char **atserver_host, int *atserver_port) {
  int ret = 1;

  atclient_connection atdirectory_conn;
  atclient_connection_init(&atdirectory_conn, ATCLIENT_CONNECTION_TYPE_ATDIRECTORY);

  const size_t recvsize = 1024;
  unsigned char recv[recvsize];
  memset(recv, 0, sizeof(unsigned char) * recvsize);
  size_t recvlen = 0;

  char *atsign_without_at_symbol = NULL;
  char *cmd = NULL;

  if ((ret = atclient_connection_connect(&atdirectory_conn, atdirectory_host, atdirectory_port)) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atclient_connection_connect: %d\n", ret);
    goto exit;
  }

  if ((ret = atclient_stringutils_atsign_without_at_symbol(atsign, &atsign_without_at_symbol)) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atclient_stringutils_atsign_without_at_symbol: %d\n", ret);
    goto exit;
  }

  size_t cmdsize = (strlen(atsign_without_at_symbol)) + strlen("\n") + 1;
  cmd = malloc(sizeof(char) * cmdsize);
  if (cmd == NULL) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "Failed to allocate memory for cmd\n");
    ret = 1;
    goto exit;
  }
  snprintf(cmd, cmdsize, "%s\n", atsign_without_at_symbol);

  if ((ret = atclient_connection_send(&atdirectory_conn, (unsigned char *)cmd, cmdsize - 1, recv, recvsize,
                                      &recvlen)) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atclient_connection_send: %d\n", ret);
    goto exit;
  }

  if (recvlen == 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "No data received from atdirectory\n");
    ret = 1;
    goto exit;
  }

  // recv has something like `228aafb0-94d3-5aa2-a3b3-e36af115480d.swarm0002.atsign.zone:6943`
  // we need to split it into host and port
  char *host = strtok((char *)recv, ":");
  char *portstr = strtok(NULL, ":");
  if (portstr == NULL) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "Failed to parse port from atdirectory response\n");
    ret = 1;
    goto exit;
  }

  *atserver_host = strdup(host);
  if(*atserver_host == NULL) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "Failed to allocate memory for atserver_host\n");
    *atserver_host = NULL;
    ret = 1;
    goto exit;
  }
  *atserver_port = atoi(portstr);

  ret = 0;
  goto exit;
exit: {
  free(atsign_without_at_symbol);
  free(cmd);
  atclient_connection_free(&atdirectory_conn);
  return ret;
}
}

int atclient_utils_populate_atkeys_from_homedir(atclient_atkeys *atkeys, const char *atsign)
{
  int ret = 1;

  struct passwd *pw = getpwuid(getuid());
  const char *homedir = pw->pw_dir;

  const size_t atkeyspathsize = strlen(homedir) + strlen("/.atsign/keys/") + strlen(atsign) + strlen("_key.atKeys") + 1;
  char atkeyspath[atkeyspathsize];

  snprintf(atkeyspath, atkeyspathsize, "%s/.atsign/keys/%s_key.atKeys", homedir, atsign);

  if ((ret = atclient_atkeys_populate_from_path(atkeys, atkeyspath)) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "Failed to populate atkeys from path: %d\n", ret);
    goto exit;
  }

  goto exit;

exit: { return ret; }
}