#include "atauth/atauth_fetch_home_dir.h"
#include "atlogger/atlogger.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// imports for windows
#if defined(_WIN32) || defined(_WIN64)
#include <shlobj.h> // For SHGetFolderPathA
#include <windows.h>
#define PATH_SEPARATOR '\\'
// imports for linux
#elif defined(__linux__)
#include <linux/limits.h>
#include <unistd.h>
#include <pwd.h>
#define PATH_SEPARATOR '/'
// imports for all other platforms
#else
#include <pwd.h>
#include <unistd.h>
#include<limits.h>
#define PATH_SEPARATOR '/'
#endif


int atauth_get_home_directory(char *home_dir) {
    home_dir = malloc(sizeof(char) * PATH_MAX);

#if defined(_WIN32) || defined(_WIN64)
    char *home = getenv("USERPROFILE");
    if (home == NULL) {
        char path[MAX_PATH];
        if (SUCCEEDED(SHGetFolderPathA(NULL, CSIDL_PROFILE, NULL, 0, path))) {
            strncpy(home_dir, path, PATH_MAX - 1);
            home_dir[PATH_MAX - 1] = '\0';
        } else {
            return -2;
        }
    } else {
        strncpy(home_dir, home, PATH_MAX - 1);
        home_dir[PATH_MAX - 1] = '\0';
    }
#else
    char *home = getenv("HOME");
    if (home == NULL) {
        struct passwd *pw = getpwuid(getuid());
        if (pw == NULL || pw->pw_dir == NULL) {
            atlogger_log("atcommons_get_home_directory", ATLOGGER_LOGGING_LEVEL_ERROR,
                         "Could not allocate memory for pwd string\n");
            return -1;
        }
        strncpy(home_dir, pw->pw_dir, PATH_MAX - 1);
        home_dir[PATH_MAX - 1] = '\0';
    } else {
        strncpy(home_dir, home, PATH_MAX - 1);
        home_dir[PATH_MAX - 1] = '\0';
    }
#endif

    // Ensure the path ends with the path separator
    size_t len = strlen(home_dir);
    if (home_dir[len - 1] != PATH_SEPARATOR) {
        if (len < PATH_MAX - 1) {
            home_dir[len] = PATH_SEPARATOR;
            home_dir[len + 1] = '\0';
        } else {
            return -3; // Path is too long to append separator
        }
    }

    return 0;
}
