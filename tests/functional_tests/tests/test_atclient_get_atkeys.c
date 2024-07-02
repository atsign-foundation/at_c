#include <atclient/atclient.h>
#include <atlogger/atlogger.h>
#include <functional_tests/helpers.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define TAG "test_atclient_get_atkeys"

#define SCAN_REGEX ".*"

#define ATSIGN1 "@12alpaca"

static int test_1_atclient_get_atkeys(atclient *ctx, const char *scan_regex, const bool showhidden);
static int test_2_atclient_get_atkeys_null(atclient *ctx, const char *scan_regex, const bool showhidden);

int main() {
  int ret = 1;

  atclient atclient1;
  atclient_init(&atclient1);

  atclient atkeys1;
  atclient_atkeys_init(&atkeys1);

  if ((ret = functional_tests_pkam_auth(&atclient1, &atkeys1, ATSIGN1, strlen(ATSIGN1))) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "functional_tests_pkam_auth failed: %d", ret);
    goto exit;
  }

  if ((ret = test_1_atclient_get_atkeys(&atclient1, SCAN_REGEX, false)) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "test_1_atclient_get_atkeys failed: %d", ret);
    goto exit;
  }

  if ((ret = test_2_atclient_get_atkeys_null(&atclient1, SCAN_REGEX, false)) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "test_2_atclient_get_atkeys_null failed: %d", ret);
    goto exit;
  }

  ret = 0;
  goto exit;
exit: {
  atclient_free(&atclient1);
  return ret;
}
}

static int test_1_atclient_get_atkeys(atclient *ctx, const char *scan_regex, const bool showhidden) {
  int ret = 1;

  atclient_atkey *atkey_array = NULL;
  size_t atkey_array_len = 0;

  if ((ret = atclient_get_atkeys(ctx, scan_regex, showhidden, atkey_array, &atkey_array_len)) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atclient_get_atkeys failed: %d", ret);
    goto exit;
  }

  ret = 0;
  goto exit;
exit: { return ret; }
}

static int test_2_atclient_get_atkeys_null(atclient *ctx, const char *scan_regex, const bool showhidden) {
  int ret = 1;

  if ((ret = atclient_get_atkeys(ctx, scan_regex, showhidden, NULL, NULL)) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atclient_get_atkeys failed: %d", ret);
    goto exit;
  }

  ret = 0;
  goto exit;
exit: { return ret; }
}
