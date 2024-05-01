#include <pwd.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include "functional_tests/config.h"

int get_atkeys_path(char *atsign, const size_t atsignlen, char *path, const size_t pathsize, size_t *pathlen) {
  // struct passwd *pw = getpwuid(getuid());
  // const char *homedir = pw->pw_dir;
  // const size_t kpathlen = strlen(homedir) + strlen("/.atsign/keys/") + atsignlen + strlen("_key.atkeys") + 1;
  // if (kpathlen > pathsize) {
  //   return 1;
  // }
  // memset(path, 0, sizeof(char) * pathsize);
  // snprintf(path, pathsize, "%s/.atsign/keys/%s_key.atkeys", homedir, atsign);
  // *pathlen = kpathlen;

  // get present working directory
  char cwd[256];
  memset(cwd, 0, sizeof(char) * 256);
  if (getcwd(cwd, 256) == NULL) {
    return 1;
  }
  // append /../keys
  snprintf(path, pathsize, "keys/%.*s_key.atKeys", cwd, (int) atsignlen, atsign);
  *pathlen = strlen(path);

  return 0;
}
