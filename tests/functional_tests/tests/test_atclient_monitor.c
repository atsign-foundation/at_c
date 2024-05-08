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
#include <pthread.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define TAG "test_atclient_monitor"

#define ATKEY_KEY "test_atclient_monitor"
#define ATKEY_NAMESPACE "functional_tests"
#define ATKEY_SHAREDBY FIRST_ATSIGN
#define ATKEY_SHAREDWITH SECOND_ATSIGN
#define ATKEY_VALUE "Test Value 12345 Meow"

#define MONITOR_REGEX "functional_tests"

static int monitor_pkam_auth(atclient *monitor_conn, const atclient_atkeys *atkeys, const char *atsign, const size_t atsignlen);
static void *heartbeat_handler(void *monitor_conn);
static int test_1_start_monitor(atclient *monitor_conn);
static int test_2_start_heartbeat(atclient *monitor_conn, pthread_t *tid);
static int test_3_stop_heartbeat(pthread_t *tid);

int main() {
  int ret = 1;

  atlogger_set_logging_level(ATLOGGER_LOGGING_LEVEL_DEBUG);

  atclient atclient1;
  atclient_init(&atclient1);
  atclient_atkeys atkeys_sharedby;
  atclient_atkeys_init(&atkeys_sharedby);

  atclient monitor_conn;
  atclient_init(&monitor_conn);
  atclient_atkeys atkeys_sharedwith;
  atclient_atkeys_init(&atkeys_sharedwith);

  pthread_t tid;

  if((ret = functional_tests_set_up_atkeys(&atkeys_sharedby, ATKEY_SHAREDBY, strlen(ATKEY_SHAREDBY))) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "Failed to set up atkeys_sharedby: %d\n", ret);
    goto exit;
  }

  if ((ret = functional_tests_pkam_auth(&atclient1, &atkeys_sharedby, ATKEY_SHAREDBY, strlen(ATKEY_SHAREDBY))) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "Failed to authenticate with PKAM: %d\n", ret);
    goto exit;
  }

  if((ret = functional_tests_set_up_atkeys(&atkeys_sharedwith, ATKEY_SHAREDWITH, strlen(ATKEY_SHAREDWITH))) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "Failed to set up atkeys_sharedby: %d\n", ret);
    goto exit;
  }

  if ((ret = monitor_pkam_auth(&monitor_conn, &atkeys_sharedwith, ATKEY_SHAREDWITH, strlen(ATKEY_SHAREDWITH))) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "Failed to authenticate with PKAM: %d\n", ret);
    goto exit;
  }

  if ((ret = test_1_start_monitor(&monitor_conn)) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "test_1_start_monitor: %d\n", ret);
    goto exit;
  }

  if ((ret = test_2_start_heartbeat(&monitor_conn, &tid)) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "test_2_start_heartbeat: %d\n", ret);
    goto exit;
  }

  if ((ret = test_3_stop_heartbeat(&tid)) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "test_3_stop_heartbeat: %d\n", ret);
    goto exit;
  }

  goto exit;
exit: {
  atclient_atkeys_free(&atkeys_sharedby);
  atclient_atkeys_free(&atkeys_sharedwith);
  atclient_free(&atclient1);
  atclient_free(&monitor_conn);
  return ret;
}
}

static void *heartbeat_handler(void *monitor_conn) {
  while (true) {
    atclient_send_heartbeat((atclient *)monitor_conn);
    sleep(30);
  }
}

static int test_1_start_monitor(atclient *monitor_conn) {
  int ret = 1;

  atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_INFO, "test_1_start_monitor Start\n");

  ret = atclient_monitor_start(monitor_conn, MONITOR_REGEX, strlen(MONITOR_REGEX));
  if (ret != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "Failed to start monitor: %d\n", ret);
    goto exit;
  }
  atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_INFO, "Started monitor\n");

  goto exit;

exit: {
  atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_INFO, "test_1_start_monitor End: %d\n", ret);
  return ret;
}
}

static int test_2_start_heartbeat(atclient *monitor_conn, pthread_t *tid) {
  int ret = 1;

  atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_INFO, "test_2_start_heartbeat Start\n");

  ret = pthread_create(tid, NULL, heartbeat_handler, monitor_conn);
  if (ret != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "Failed to start heartbeat handler: %d\n", ret);
    goto exit;
  }

  ret = 0;
  goto exit;
exit: {
  atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_INFO, "test_2_start_heartbeat End: %d\n", ret);
  return ret;
}
}

static int test_3_stop_heartbeat(pthread_t *tid) {
  int ret = 1;

  atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_INFO, "test_3_stop_heartbeat Start\n");

  ret = pthread_cancel(*tid);
  if (ret != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "Failed to stop heartbeat handler: %d\n", ret);
    goto exit;
  }

  ret = 0;
  goto exit;
exit: {
  atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_INFO, "test_3_stop_heartbeat End: %d\n", ret);
  return ret;
}
}

static int monitor_pkam_auth(atclient *monitor_conn, const atclient_atkeys *atkeys, const char *atsign, const size_t atsignlen) {
  int ret = 1;

  atclient_connection root_conn;
  atclient_connection_init(&root_conn);

  if ((ret = atclient_connection_connect(&root_conn, ROOT_HOST, ROOT_PORT)) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atclient_connection_connect: %d\n", ret);
    goto exit;
  }

  if ((ret = atclient_monitor_pkam_authenticate(monitor_conn, &root_conn, atkeys, atsign)) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atclient_monitor_pkam_authenticate: %d\n", ret);
    goto exit;
  }

  ret = 0;
  goto exit;
exit: {
  atclient_connection_free(&root_conn);
  return ret;
}
}