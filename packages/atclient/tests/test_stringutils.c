#include "atclient/string_utils.h"
#include "atlogger/atlogger.h"
#include <stddef.h>
#include <stdlib.h> // IWYU pragma: keep
#include <string.h>

#define TAG "test_stringutils"

static int test_1_starts_with();
static int test_2_ends_with();
static int test_3_trim_whitespace();

int main() {
  int ret = 1;

  atlogger_set_logging_level(ATLOGGER_LOGGING_LEVEL_DEBUG);

  if ((ret = test_1_starts_with()) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "test_1_starts_with: %d\n", ret);
    goto exit;
  }

  if ((ret = test_2_ends_with()) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "test_2_ends_with: %d\n", ret);
    goto exit;
  }

  if ((ret = test_3_trim_whitespace()) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "test_3_trim_whitespace: %d\n", ret);
    goto exit;
  }

  ret = 0;
  goto exit;
exit: { return ret; }
}

static int test_1_starts_with() {
  int ret = 1;

  atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_INFO, "test_1_starts_with Begin\n");

  const char *string = "@bob";

  // 1a. @bob starts with @
  if (atclient_string_utils_starts_with(string, "@") != true) {
    ret = 1;
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atclient_stringutils_starts_with: %d | %s starts with %s\n", ret,
                 string, "@");
    goto exit;
  }

  // 1b. @bob does not start with 123
  if (atclient_string_utils_starts_with(string, "123") != false) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atclient_stringutils_starts_with: %d | %s starts with %s\n", ret,
                 string, "bob");
    ret = 1;
    goto exit;
  }

  ret = 0;
  goto exit;
exit: {
  atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_INFO, "test_1_starts_with End\n");
  return ret;
}
}

static int test_2_ends_with() {
  int ret = 1;

  atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_INFO, "test_2_ends_with Begin\n");

  const char *string = "root.atsign.org:64";

  // 2a. root.atsign.org:64 ends with 64
  if (atclient_string_utils_ends_with(string, "64") != true) {
    ret = 1;
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atclient_string_utils_ends_with: %d | %s ends with %s\n", ret,
                 string, "64");
    goto exit;
  }

  // 2b. root.atsign.org:64 does not end with org
  if (atclient_string_utils_ends_with(string, "org") != 0) {
    ret = 1;
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atclient_string_utils_ends_with: %d | %s ends with %s\n", ret,
                 string, "org");
    goto exit;
  }

  ret = 0;
  goto exit;
exit: {
  atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_INFO, "test_2_ends_with End\n");
  return ret;
}
}

static int test_3_trim_whitespace() {
  int ret = 1;

  atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_INFO, "test_3_trim_whitespace Begin\n");

  const char *string = "       scan jeremy_0\n ";

  const size_t outsize = 4096;
  char out[outsize];
  size_t outlen = 0;

  const char *expectedresult = "scan jeremy_0";
  if ((ret = atclient_string_utils_trim_whitespace(string, strlen(string), out, outsize, &outlen)) != 0) {
    ret = 1;
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atclient_string_utils_trim_whitespace: %d | %s\n", ret, string);
    goto exit;
  }

  if (strcmp(out, expectedresult) != 0) {
    ret = 1;
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atclient_string_utils_trim_whitespace: \"%s\" != \"%s\"\n", string,
                 expectedresult);
    goto exit;
  }

  ret = 0;
  goto exit;
exit: {
  atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_INFO, "test_3_trim_whitespace End\n");
  return ret;
}
}