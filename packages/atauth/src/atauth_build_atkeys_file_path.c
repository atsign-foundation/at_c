#include "atauth/atauth_build_atkeys_file_path.h"
#include "atauth/atauth_fetch_home_dir.h"

#include <atlogger/atlogger.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define DEFAULT_ATKEYS_DIR ".atsign/keys/"
#define ATKEYS_EXTENSION ".atKeys"
#define TAG "build_atkeys_filepath"

int atauth_build_atkeys_file_path(char **atkeys_path, const char *atsign) {
  int ret = 0;
  char *home_dir = NULL;

  if ((ret = atauth_get_home_directory(&home_dir)) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_DEBUG, "atauth_get_home_directory: %d/n", ret);
    return ret;
  }

  // Calculate path length and allocate memory
  const int path_len =
      snprintf(NULL, 0, "%s%s%s_key%s", home_dir, DEFAULT_ATKEYS_DIR, atsign, ATKEYS_EXTENSION) + 1; // +1 for \0
  *atkeys_path = malloc(sizeof(char) * path_len);
  if (*atkeys_path == NULL) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "Could not allocate memory for atkeys_fp\n");
    ret = -1;
    goto exit;
  }

  snprintf(*atkeys_path, path_len, "%s%s%s_key%s", home_dir, DEFAULT_ATKEYS_DIR, atsign, ATKEYS_EXTENSION);

exit:
  return ret;
}
