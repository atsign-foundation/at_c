#include "atcommons/atcommons_fetch_home_dir.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/syslimits.h>

#if defined(_WIN32) || defined(_WIN64)
#include <windows.h>
#else
#include <unistd.h>
#include <pwd.h>
#endif

int atcommons_get_home_directory(char *home_dir) {
  if (home_dir == NULL) {
    return -1;
  }

#if defined(_WIN32) || defined(_WIN64)
  char *home = getenv("USERPROFILE");
  if (home == NULL) {
    char path[MAX_PATH];
    if (SUCCEEDED(SHGetFolderPathA(NULL, CSIDL_PROFILE, NULL, 0, path))) {
      strncpy(home_dir, path, MAX_PATH);
      home_dir[MAX_PATH - 1] = '\0';
    } else {
      return -1;
    }
  } else {
    strncpy(home_dir, home, MAX_PATH);
    home_dir[MAX_PATH - 1] = '\0';
  }

#else
  char *home = getenv("HOME");
  if (home == NULL) {
    struct passwd *pw = getpwuid(getuid());
    if (pw == NULL || pw->pw_dir == NULL) {
      return -1;
    }
    strncpy(home_dir, pw->pw_dir, PATH_MAX);
    home_dir[PATH_MAX - 1] = '\0';
  } else {
    strncpy(home_dir, home, PATH_MAX);
    home_dir[PATH_MAX - 1] = '\0';
  }
#endif

  return 0;
}
