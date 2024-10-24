#include "atauth/atauth_build_atkeys_file_path.h"
#include "atcommons/atcommons_fetch_home_dir.h"

#include <atlogger/atlogger.h>
#include <stdio.h>
#include <string.h>

#define DEFAULT_ATKEYS_DIR ".atsign/keys/"
#define ATKEYS_EXTENSION ".atKeys"

int atauth_build_atkeys_file_path(char *atkeys_path, size_t *atkeys_path_len, char *atsign) {
  int ret = 0;

  if (atkeys_path_len == NULL) {
    return -1;
  }

  char home_dir[512];

  if ((ret = atcommons_get_home_directory(home_dir)) != 0) {
    return ret;
  }

  // Assumes that 'atcommons_get_home_directory()' returns home_dir with a trailing '/'
  if (atkeys_path == NULL) { // Fetch the length to be written
    *atkeys_path_len = snprintf(NULL, 0, "%s%s%s_key%s", home_dir, DEFAULT_ATKEYS_DIR, atsign, ATKEYS_EXTENSION);
    return 1; // Return 1 to indicate this function cannot be run with a NULL 'atkeys_path'
  }

  snprintf(atkeys_path, *atkeys_path_len, "%s%s%s_key%s", home_dir, DEFAULT_ATKEYS_DIR, atsign, ATKEYS_EXTENSION);

  return ret;
}
