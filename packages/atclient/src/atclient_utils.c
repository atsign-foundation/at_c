#include "atclient/atclient_utils.h"
#include "atclient/atkeys.h"
#include "atclient/connection.h"
#include "atclient/string_utils.h"
#include <atchops/platform.h>
#include <atlogger/atlogger.h>
#include <pwd.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define TAG "atclient_utils"

int atclient_utils_find_atserver_address(const char *atdirectory_host, const int atdirectory_port, const char *atsign,
                                         char **atserver_host, int *atserver_port) {
  int ret = 1;

  atclient_connection atdirectory_conn;
  atclient_connection_init(&atdirectory_conn, ATCLIENT_CONNECTION_TYPE_ATDIRECTORY);

  const size_t recv_size = 1024;
  unsigned char recv[recv_size];
  memset(recv, 0, sizeof(unsigned char) * recv_size);
  size_t recv_len = 0;

  char *atsign_without_at_symbol = NULL;
  char *cmd = NULL;

  if ((ret = atclient_connection_connect(&atdirectory_conn, atdirectory_host, atdirectory_port)) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atclient_connection_connect: %d\n", ret);
    goto exit;
  }

  if ((ret = atclient_string_utils_atsign_without_at(atsign, &atsign_without_at_symbol)) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atclient_string_utils_atsign_without_at: %d\n", ret);
    goto exit;
  }

  const size_t cmd_size = (strlen(atsign_without_at_symbol)) + strlen("\n") + 1;
  cmd = malloc(sizeof(char) * cmd_size);
  if (cmd == NULL) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "Failed to allocate memory for cmd\n");
    ret = 1;
    goto exit;
  }
  snprintf(cmd, cmd_size, "%s\n", atsign_without_at_symbol);

  if ((ret = atclient_connection_send(&atdirectory_conn, (unsigned char *)cmd, cmd_size - 1, recv, recv_size,
                                      &recv_len)) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atclient_connection_send: %d\n", ret);
    goto exit;
  }

  if (recv_len == 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "No data received from atdirectory\n");
    ret = 1;
    goto exit;
  }

  // recv has something like `228aafb0-94d3-5aa2-a3b3-e36af115480d.swarm0002.atsign.zone:6943`
  // we need to split it into host and port
  char *host = strtok((char *)recv, ":");
  char *port_str = strtok(NULL, ":");
  if (port_str == NULL) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "Failed to parse port from atdirectory response\n");
    ret = 1;
    goto exit;
  }

  *atserver_host = strdup(host);
  if (*atserver_host == NULL) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "Failed to allocate memory for atserver_host\n");
    *atserver_host = NULL;
    ret = 1;
    goto exit;
  }
  *atserver_port = atoi(port_str);

  ret = 0;
  goto exit;
exit: {
  free(atsign_without_at_symbol);
  free(cmd);
  atclient_connection_free(&atdirectory_conn);
  return ret;
}
}

int atclient_utils_populate_atkeys_from_homedir(atclient_atkeys *atkeys, const char *atsign) {
  int ret = 1;

  /*
   * 1. Validate arguments
   */
  if (atkeys == NULL) {
    ret = 1;
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atkeys is NULL\n");
    return ret;
  }

  if (atsign == NULL) {
    ret = 1;
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atsign is NULL\n");
    return ret;
  }

  struct passwd *pw = getpwuid(getuid());
  const char *homedir = pw->pw_dir;

  const size_t atkeys_path_size =
      strlen(homedir) + strlen("/.atsign/keys/") + strlen(atsign) + strlen("_key.atKeys") + 1;
  char atkeys_path[atkeys_path_size];

  snprintf(atkeys_path, atkeys_path_size, "%s/.atsign/keys/%s_key.atKeys", homedir, atsign);

  if ((ret = atclient_atkeys_populate_from_path(atkeys, atkeys_path)) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "Failed to populate atkeys from path: %d\n", ret);
    goto exit;
  }

  ret = 0;
  goto exit;

exit: { return ret; }
}

int atclient_utils_find_index_past_at_prompt(const unsigned char *read_buf, size_t read_n, size_t *read_i) {
  // NOTE: if you change this if, check the second while loop
  // it depends on this guard clause
  *read_i = 0;
  if (read_n != 0 && read_buf[0] != '@') { // Doesn't start with a prompt
    return 0;
  }

  if (read_n >= 5 && strncmp((const char *)read_buf, "@null", 5) == 0) {
    *read_i = 1;
    return 0;
  }

  while (++*read_i < read_n && read_buf[*read_i] != ':')
    ;                      // Walks forward to the end of the buffer or first ':'
  if (*read_i == read_n) { // Past the end of the buffer, did not find `:`
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR,
                 "Unable to find command result token `:`, connection should be reset\n");
    return 1;
  }
  // We are at a `:`
  while (--*read_i > 0 && read_buf[*read_i] != '@')
    ; // Walk backwards to the first '@' we find
  // We are at the first character or last '@' before a `:`
  // but the first character is '@' so we are at '@'

  ++*read_i; // move forward one to be after the '@'

  return 0;
}
