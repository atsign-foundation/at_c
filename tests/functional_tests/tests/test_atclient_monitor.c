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
#define ATKEY_VALUE "Test Value Meow 123!"

static int test_1_start_monitor(atclient *monitor, const atclient_atkeys *atkeys);
static int test_2_send_notification(atclient *atclient);
static int test_3_read_monitor(atclient *monitor);

int main() {
  int ret = 1;

  atlogger_set_logging_level(ATLOGGER_LOGGING_LEVEL_DEBUG);

  atclient atclient_conn; // sharedby
  atclient_init(&atclient_conn);

  atclient monitor_conn; // sharedwith
  atclient_init(&monitor_conn);

  const size_t pathsize = 1024;
  char path[pathsize];
  memset(path, 0, sizeof(char) * pathsize);
  size_t pathlen = 0;

  atclient_atkeys atkeys;
  atclient_atkeys_init(&atkeys);

  ret = functional_tests_pkam_auth(&atclient_conn, ATKEY_SHAREDBY);
  if (ret != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "Failed to authenticate.\n");
    goto exit;
  }

  ret = functional_tests_get_atkeys_path(ATKEY_SHAREDWITH, strlen(ATKEY_SHAREDWITH), path, pathsize, &pathlen);
  if (ret != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "Failed to get atkeys path: %d\n", ret);
    goto exit;
  }

  ret = atclient_atkeys_populate_from_path(&atkeys, path);
  if (ret != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "Failed to populate atkeys: %d\n", ret);
    goto exit;
  }

  ret = test_1_start_monitor(&monitor_conn, &atkeys);
  if (ret != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "Failed test_1.\n");
    goto exit;
  }

  ret = test_2_send_notification(&atclient_conn);
  if (ret != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "Failed test_2.\n");
    goto exit;
  }

  ret = test_3_read_monitor(&monitor_conn);
  if (ret != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "Failed test_3.\n");
    goto exit;
  }

exit: {
  atclient_free(&atclient_conn);
  atclient_atkeys_free(&atkeys);
  atclient_free(&monitor_conn);
  return ret;
}
}

static int test_1_start_monitor(atclient *monitor, const atclient_atkeys *atkeys) {
  int ret = 1;

  ret = atclient_monitor_start_connection(monitor, ROOT_HOST, ROOT_PORT, ATKEY_SHAREDWITH, atkeys, ATKEY_NAMESPACE);
  if (ret != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "Failed to start monitor: %d\n", ret);
    goto exit;
  }

exit: { return ret; }
}

static int test_2_send_notification(atclient *atclient) {
  int ret = 1;

  atclient_atkey atkey;
  atclient_atkey_init(&atkey);

  atclient_notify_params params;
  atclient_notify_params_init(&params);

  ret = atclient_atkey_create_sharedkey(&atkey, ATKEY_KEY, strlen(ATKEY_KEY), ATKEY_SHAREDBY, strlen(ATKEY_SHAREDBY),
                                        ATKEY_SHAREDWITH, strlen(ATKEY_SHAREDWITH), ATKEY_NAMESPACE,
                                        strlen(ATKEY_NAMESPACE));
  if (ret != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atclient_atkey_create_sharedkey: %d\n", ret);
    goto exit;
  }

  atclient_notify_params_create(&params, ATCLIENT_NOTIFY_OPERATION_UPDATE, &atkey, ATKEY_VALUE);

  ret = atclient_notify(atclient, &params, NULL);
  if (ret != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "Failed to send notification");
    goto exit;
  }

exit: {
  atclient_atkey_free(&atkey);
  return ret;
}
}

static int test_3_read_monitor(atclient *monitor) {
  int ret = 1;

  atclient_monitor_message message;
  atclient_monitor_message_init(&message);

  ret = atclient_monitor_read(monitor, &message);
  if (ret != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "Failed to read monitor");
    goto exit;
  }

  if (message.type != ATCLIENT_MONITOR_MESSAGE_TYPE_NOTIFICATION) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "Expected notification, got %d", message.type);
    goto exit;
  }

  atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_DEBUG, "Notification: %s\n", message.notification.value);
exit: {
  atclient_monitor_message_free(&message);
  return ret;
}
}
