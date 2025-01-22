#include "atclient/atclient_utils.h"
#include "atclient/atkeys.h"
#include "atdirectory.h"
#include <atchops/platform.h>
#include <atlogger/atlogger.h>
#include <pwd.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define TAG "atclient_utils"

int atclient_utils_find_atserver_address(const char *atdirectory_host, const uint16_t atdirectory_port,
                                         const char *atsign, char **atserver_host, uint16_t *atserver_port) {
  return atdirectory_lookup_once(atdirectory_host, atdirectory_port, atsign, atserver_host, atserver_port);
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
