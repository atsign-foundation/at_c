#include "atclient/stringutils.h"
#include "atlogger/atlogger.h"
#include <stddef.h>
#include <stdlib.h> // IWYU pragma: keep
#include <string.h>

#define TAG "test_stringutils"

int main() {
  int ret = 1;

  atlogger_set_logging_level(ATLOGGER_LOGGING_LEVEL_INFO);

  const size_t outlen = 4096;
  char *out = (char *)malloc(sizeof(char) * outlen);
  memset(out, 0, sizeof(char) * outlen);
  size_t outolen = 0;

  const size_t stringlen = 4096;
  char *string = (char *)malloc(sizeof(char) * stringlen);
  memset(string, 0, sizeof(char) * stringlen);
  strcpy(string, "@bob");

  const size_t tokenslen = 64;
  char *tokens[tokenslen];
  memset(tokens, 0, sizeof(char *) * tokenslen); // set all pointers to NULL (0
  size_t tokensolen = 0;

  int startswith;

  // 1a. @bob starts with @
  startswith = atclient_stringutils_starts_with(string, strlen(string), "@", strlen("@"));
  if (startswith != 1) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR,
                          "atclient_stringutils_starts_with: %d | %s starts with %s\n", ret, string, "@");
    ret = 1;
    goto exit;
  }

  // 1b. @bob does not start with 123
  startswith = atclient_stringutils_starts_with(string, strlen(string), "123", strlen("123"));
  if (startswith != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR,
                          "atclient_stringutils_starts_with: %d | %s starts with %s\n", ret, string, "bob");
    ret = 1;
    goto exit;
  }

  int endswith;
  strcpy(string, "root.atsign.org:64");
  // 2a. root.atsign.org:64 ends with 64
  endswith = atclient_stringutils_ends_with(string, strlen(string), "64", strlen("64"));
  if (endswith != 1) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atclient_stringutils_ends_with: %d | %s ends with %s\n",
                          ret, string, "64");
    ret = 1;
    goto exit;
  }

  // 2b. root.atsign.org:64 does not end with org
  endswith = atclient_stringutils_ends_with(string, strlen(string), "org", strlen("org"));
  if (endswith != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atclient_stringutils_ends_with: %d | %s ends with %s\n",
                          ret, string, "org");
    ret = 1;
    goto exit;
  }

  // 3. trim whitespace and newline
  strcpy(string, "   scan jeremy_0\n ");
  const char *expectedresult = "scan jeremy_0";
  ret = atclient_stringutils_trim_whitespace(string, strlen(string), out, outlen, &outolen);
  if (ret != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atclient_stringutils_trim_whitespace: %d | %s\n", ret,
                          string);
    ret = 1;
    goto exit;
  }

  if (strncmp(out, expectedresult, strlen(expectedresult)) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atclient_stringutils_trim_whitespace: \"%s\" != \"%s\"\n",
                          string, expectedresult);
    ret = 1;
    goto exit;
  }

  ret = 0;
  goto exit;
exit: {
  free(out);
  free(string);
  return ret;
}
}
