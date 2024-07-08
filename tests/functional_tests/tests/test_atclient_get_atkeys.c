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
static int test_3_atclient_get_atkeys_null_ctx(const char *scan_regex, const bool showhidden);
static int test_4_atclient_get_atkeys_null_regex(atclient *ctx, const char *scan_regex, const bool showhidden);

int main() {
  int ret = 1;

  atlogger_set_logging_level(ATLOGGER_LOGGING_LEVEL_DEBUG);

  atclient atclient1;
  atclient_init(&atclient1);

  atclient atkeys1;
  atclient_atkeys_init(&atkeys1);

  if ((ret = functional_tests_set_up_atkeys(&atkeys1, ATSIGN1, strlen(ATSIGN1))) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "functional_tests_set_up_atkeys failed: %d\n", ret);
    goto exit;
  }

  if ((ret = functional_tests_pkam_auth(&atclient1, &atkeys1, ATSIGN1, strlen(ATSIGN1))) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "functional_tests_pkam_auth failed: %d\n", ret);
    goto exit;
  }

  if ((ret = test_1_atclient_get_atkeys(&atclient1, SCAN_REGEX, false)) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "test_1_atclient_get_atkeys failed: %d\n", ret);
    goto exit;
  }

  if ((ret = test_2_atclient_get_atkeys_null(&atclient1, SCAN_REGEX, false)) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "test_2_atclient_get_atkeys_null failed: %d", ret);
    goto exit;
  }

  if((ret = test_3_atclient_get_atkeys_null_ctx(SCAN_REGEX, false)) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "test_3_atclient_get_atkeys_null_ctx failed: %d", ret);
    goto exit;
  }

  if((ret = test_4_atclient_get_atkeys_null_regex(&atclient1, SCAN_REGEX, false)) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "test_4_atclient_get_atkeys_null_regex failed: %d", ret);
    goto exit;
  }

  ret = 0;
  goto exit;
exit: {
  atclient_free(&atclient1);
  atclient_atkeys_free(&atkeys1);
  return ret;
}
}

static int test_1_atclient_get_atkeys(atclient *ctx, const char *scan_regex, const bool showhidden) {
  int ret = 1;

  atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_DEBUG, "test_1_atclient_get_atkeys\n");

  atclient_atkey *atkey_array = NULL;
  size_t atkey_array_len = 0;

  if ((ret = atclient_get_atkeys(ctx, scan_regex, showhidden, 8192, &atkey_array, &atkey_array_len)) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atclient_get_atkeys failed: %d", ret);
    goto exit;
  }

  char buf[4096];
  memset(buf, 0, sizeof(char) * 4096);
  size_t bufolen = 0;

  for(size_t i = 0; i < atkey_array_len; i++) {
    atclient_atkey_to_string(&atkey_array[i], buf, 4096, &bufolen);
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_DEBUG, "atkey_array[%zu]: %s\n", i, buf);
    memset(buf, 0, sizeof(char) * 4096);
  }

  for (size_t i = 0; i < atkey_array_len; i++) {
    atclient_atkey_free(&atkey_array[i]);
  }

  ret = 0;
  goto exit;
exit: {
  atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_DEBUG, "test_1_atclient_get_atkeys: %d\n", ret);
  return ret;
}
}

static int test_2_atclient_get_atkeys_null(atclient *ctx, const char *scan_regex, const bool showhidden) {
  int ret = 1;

  atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_DEBUG, "test_2_atclient_get_atkeys_null\n");

  if (atclient_get_atkeys(ctx, scan_regex, showhidden, 8192, NULL, NULL) == 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atclient_get_atkeys passed when it should not have: %d\n", ret);
    ret = 1;
    goto exit;
  }

  atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_DEBUG, "atclient_get_atkeys failed as expected\n");

  ret = 0;
  goto exit;
exit: {
  atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_DEBUG, "test_2_atclient_get_atkeys_null: %d\n", ret);
  return ret;
}
}

static int test_3_atclient_get_atkeys_null_ctx(const char *scan_regex, const bool showhidden)
{
  int ret = 1;

  atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_DEBUG, "test_3_atclient_get_atkeys_null_ctx\n");

  atclient_atkey *arr = NULL;
  size_t arrlen = 0;

  if (atclient_get_atkeys(NULL, scan_regex, showhidden, 8192, &arr, &arrlen) == 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atclient_get_atkeys passed when it should not have: %d\n", ret);
    ret = 1;
    goto exit;
  }

  atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_DEBUG, "atclient_get_atkeys failed as expected\n");

  ret = 0;
  goto exit;
exit: {
  atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_DEBUG, "test_3_atclient_get_atkeys_null_ctx: %d\n", ret);
  return ret;
}
}

static int test_4_atclient_get_atkeys_null_regex(atclient *ctx, const char *scan_regex, const bool showhidden)
{
  int ret = 1;

  atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_DEBUG, "test_4_atclient_get_atkeys_null_regex\n");

  atclient_atkey *arr = NULL;
  size_t arrlen = 0;

  if ((ret = atclient_get_atkeys(ctx, NULL, showhidden, 8192, &arr, &arrlen) != 0)) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atclient_get_atkeys failed: %d\n", ret);
    goto exit;
  }

  atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_DEBUG, "atclient_get_atkeys passed with NULL regex as expected\n");

  ret = 0;
  goto exit;
exit: {
  atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_DEBUG, "test_4_atclient_get_atkeys_null_regex: %d\n", ret);
  return ret;
}
}