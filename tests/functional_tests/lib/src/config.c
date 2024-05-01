#include <pwd.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include "functional_tests/config.h"

int functional_tests_get_atkeys_path(const char *atsign, const size_t atsignlen, char *path, const size_t pathsize, size_t *pathlen) {
  // for home directory
  struct passwd *pw = getpwuid(getuid());
  const char *homedir = pw->pw_dir;
  const size_t kpathlen = strlen(homedir) + strlen("/.atsign/keys/") + atsignlen + strlen("_key.atkeys") + 1;
  if (kpathlen > pathsize) {
    return 1;
  }
  memset(path, 0, sizeof(char) * pathsize);
  snprintf(path, pathsize, "%s/.atsign/keys/%s_key.atKeys", homedir, atsign);
  *pathlen = kpathlen;

  return 0;
}
