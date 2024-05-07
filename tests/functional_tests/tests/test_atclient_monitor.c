#include "functional_tests/config.h"
#include "functional_tests/helpers.h"
#include <atchops/aes.h>
#include <atchops/aesctr.h>
#include <atchops/base64.h>
#include <atchops/iv.h>
#include <atclient/atclient.h>
#include <atclient/encryption_key_helpers.h>
#include <atclient/monitor.h>
#include <atclient/notify.h>
#include <atclient/stringutils.h>
#include <atlogger/atlogger.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define TAG "test_atclient_monitor"

#define ATKEY_KEY "test_atclient_monitor"
#define ATKEY_NAMESPACE "functional_tests"
#define ATKEY_SHAREDBY FIRST_ATSIGN
#define ATKEY_SHAREDWITH SECOND_ATSIGN
#define ATKEY_VALUE "Test Value 12345 Meow"

#define MONITOR_REGEX "functional_tests"

static int set_up_atkeys(atclient_atkeys *atkeys);
static int test_1_start_monitor(atclient *monitor_conn, const atclient_atkeys *atkeys);

int main() {
  int ret = 1;

  atlogger_set_logging_level(ATLOGGER_LOGGING_LEVEL_DEBUG);

  atclient monitor_conn;
  atclient_init(&monitor_conn);

  atclient_atkeys atkeys;
  atclient_atkeys_init(&atkeys);

  if ((ret = set_up_atkeys(&atkeys)) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "Failed to set up atkeys: %d\n", ret);
    goto exit;
  }

  if ((ret = test_1_start_monitor(&monitor_conn, &atkeys)) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "test_1_start_monitor: %d\n", ret);
    goto exit;
  }

  goto exit;
exit: {
  atclient_free(&monitor_conn);
  atclient_atkeys_free(&atkeys);
  return ret;
}
}

static int set_up_atkeys(atclient_atkeys *atkeys) {
  int ret = 1;

  const size_t atkeyspathsize = 1024;
  char atkeyspath[atkeyspathsize];
  memset(atkeyspath, 0, atkeyspathsize);
  size_t atkeyspathlen = 0;

  ret = functional_tests_get_atkeys_path(ATKEY_SHAREDWITH, strlen(ATKEY_SHAREDWITH), atkeyspath, atkeyspathsize,
                                         &atkeyspathlen);
  if (ret != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "Failed to get atkeys path: %d\n", ret);
    goto exit;
  }

  if ((ret = atclient_atkeys_populate_from_path(atkeys, atkeyspath)) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "Failed to populate atkeys from path: %d\n", ret);
    goto exit;
  }

  goto exit;

exit: { return ret; }
}

static int test_1_start_monitor(atclient *monitor_conn, const atclient_atkeys *atkeys) {
  int ret = 1;

  atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_INFO, "test_1_start_monitor Start\n");

  atclient_connection root_conn;
  atclient_connection_init(&root_conn);

  ret = atclient_connection_connect(&root_conn, ROOT_HOST, ROOT_PORT);
  if (ret != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "Failed to connect to root server: %d\n", ret);
    goto exit;
  }
  atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_INFO, "Connected to root server\n");

  ret = atclient_start_monitor(monitor_conn, &root_conn, ATKEY_SHAREDWITH, atkeys, MONITOR_REGEX,
                               strlen(MONITOR_REGEX));
  if (ret != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "Failed to start monitor: %d\n", ret);
    goto exit;
  }
  atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_INFO, "Started monitor\n");

  goto exit;

exit: {
  atclient_connection_free(&root_conn);
  atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_INFO, "test_1_start_monitor End: %d\n", ret);
  return ret;
}
}
