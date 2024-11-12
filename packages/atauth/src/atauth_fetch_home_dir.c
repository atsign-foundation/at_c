#include "atauth/atauth_fetch_home_dir.h"
#include "atlogger/atlogger.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// Imports for Windows
#if defined(_WIN32) || defined(_WIN64)
#include <shlobj.h> // For SHGetFolderPathA
#include <windows.h>
#define PATH_SEPARATOR '\\'
#define PATH_MAX 260 // Max path length for Windows (adjustable if needed)

// Imports for Linux
#elif defined(__linux__)
#include <linux/limits.h>
#include <pwd.h>
#include <unistd.h>
#define PATH_SEPARATOR '/'

// Imports for other platforms
#else
#include <limits.h>
#include <pwd.h>
#include <unistd.h>
#define PATH_SEPARATOR '/'
#endif

#define TAG "fetch_home_dir"

int atauth_get_home_directory(char **home_dir) {
  *home_dir = malloc(PATH_MAX * sizeof(char));
  if (*home_dir == NULL) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "Unable to allocate memory for home_dir");
    return -1; // Memory allocation failure
  }

#if defined(_WIN32) || defined(_WIN64)
  // For Windows, use USERPROFILE or SHGetFolderPath
  char *home = getenv("USERPROFILE");
  if (home == NULL) {
    char path[MAX_PATH];
    if (SUCCEEDED(SHGetFolderPathA(NULL, CSIDL_PROFILE, NULL, 0, path))) {
      strncpy(*home_dir, path, PATH_MAX - 1);
      (*home_dir)[PATH_MAX - 1] = '\0';
    } else {
      free(*home_dir);
      return -2;
    }
  } else {
    strncpy(*home_dir, home, PATH_MAX - 1);
    (*home_dir)[PATH_MAX - 1] = '\0';
  }

#else
  // For Unix-like systems, use getenv("HOME") or getpwuid
  char *home = getenv("HOME");
  if (home == NULL) {
    struct passwd *pw = getpwuid(getuid());
    if (pw == NULL || pw->pw_dir == NULL) {
      atlogger_log("atcommons_get_home_directory", ATLOGGER_LOGGING_LEVEL_ERROR,
                   "Could not get user home directory.\n");
      free(*home_dir);
      return -3; // Failed to get home directory
    }
    strncpy(*home_dir, pw->pw_dir, PATH_MAX - 1);
  } else {
    strncpy(*home_dir, home, PATH_MAX - 1);
  }
#endif

  const size_t len = strlen(*home_dir);
  // Ensure the path ends with the separator
  if ((*home_dir)[len - 1] != PATH_SEPARATOR) {
    if (len < PATH_MAX - 1) {
      (*home_dir)[len] = PATH_SEPARATOR;
      (*home_dir)[len + 1] = '\0'; // Ensure null termination
    } else {
      free(*home_dir);
      return -4; // Path too long to append separator
    }
  }
  return 0;
}
