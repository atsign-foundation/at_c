#include "atauth/atauth_build_atkeys_file_path.h"
#include "atauth/atauth_fetch_home_dir.h"

#include <atlogger/atlogger.h>
#include <stdio.h>
#include <string.h>
#include <sys/_types/_size_t.h>
#include <sys/syslimits.h>

#define DEFAULT_ATKEYS_DIR ".atsign/keys/"
#define ATKEYS_EXTENSION ".atKeys"

int atauth_build_atkeys_file_path(char *atkeys_path, const char *atsign) {
  int ret = 0;
  char home_dir[PATH_MAX];
  memset(home_dir, 0, sizeof(home_dir));

  if ((ret = atauth_get_home_directory(&home_dir)) != 0) {
    atlogger_log("build atkeys fp", ATLOGGER_LOGGING_LEVEL_DEBUG, "atauth_get_home_directory: %d/n", ret);
    return ret;
  }

  atlogger_log("build atkeys fp", ATLOGGER_LOGGING_LEVEL_DEBUG, "fetched home directory: %s\n", &home_dir);

  int write_len = snprintf(atkeys_path, PATH_MAX, "%s%s%s_key%s", home_dir, DEFAULT_ATKEYS_DIR, atsign, ATKEYS_EXTENSION);
  atkeys_path[write_len - 1] = "\0";

  return ret;
}
