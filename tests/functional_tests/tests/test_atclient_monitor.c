#include "functional_tests/config.h"
#include "functional_tests/helpers.h"
#include <atchops/aes.h>
#include <atchops/aesctr.h>
#include <atchops/base64.h>
#include <atchops/iv.h>
#include <atclient/atclient.h>
#include <atclient/atclient_utils.h>
#include <atclient/encryption_key_helpers.h>
#include <atclient/monitor.h>
#include <atclient/notify.h>
#include <atclient/stringutils.h>
#include <atlogger/atlogger.h>
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

#define MONITOR_REGEX ".*"

static int monitor_pkam_auth(atclient *monitor_conn, const atclient_atkeys *atkeys, const char *atsign,
                             const size_t atsignlen);
static int send_notification(atclient *atclient);
static int monitor_for_notification(atclient *monitor_conn, atclient *atclient2);

static int test_1_start_monitor(atclient *monitor_conn);
static int test_2_send_notification(atclient *atclient);
static int test_3_monitor_for_notification(atclient *monitor_conn, atclient *atclient2);
static int test_4_re_pkam_auth_and_start_monitor(atclient *monitor_conn);
static int test_5_send_notification(atclient *atclient);
static int test_6_monitor_for_notification(atclient *monitor_conn, atclient *atclient2);

int main() {
  int ret = 1;

  atlogger_set_logging_level(ATLOGGER_LOGGING_LEVEL_DEBUG);

  atclient atclient1;
  atclient_init(&atclient1);

  atclient_atkeys atkeys_sharedby;
  atclient_atkeys_init(&atkeys_sharedby);

  atclient monitor_conn;
  atclient_monitor_init(&monitor_conn);

  atclient atclient2;
  atclient_init(&atclient2);

  atclient_atkeys atkeys_sharedwith;
  atclient_atkeys_init(&atkeys_sharedwith);

  if ((ret = functional_tests_set_up_atkeys(&atkeys_sharedby, ATKEY_SHAREDBY, strlen(ATKEY_SHAREDBY))) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "Failed to set up atkeys_sharedby: %d\n", ret);
    goto exit;
  }

  if ((ret = functional_tests_pkam_auth(&atclient1, &atkeys_sharedby, ATKEY_SHAREDBY, strlen(ATKEY_SHAREDBY))) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "Failed to authenticate with PKAM: %d\n", ret);
    goto exit;
  }

  if ((ret = functional_tests_set_up_atkeys(&atkeys_sharedwith, ATKEY_SHAREDWITH, strlen(ATKEY_SHAREDWITH))) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "Failed to set up atkeys_sharedby: %d\n", ret);
    goto exit;
  }

  if ((ret = monitor_pkam_auth(&monitor_conn, &atkeys_sharedwith, ATKEY_SHAREDWITH, strlen(ATKEY_SHAREDWITH))) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "Failed to authenticate with PKAM: %d\n", ret);
    goto exit;
  }

  atclient_monitor_set_read_timeout(&monitor_conn, 5);

  if ((ret = functional_tests_pkam_auth(&atclient2, &atkeys_sharedwith, ATKEY_SHAREDWITH, strlen(ATKEY_SHAREDWITH))) !=
      0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "Failed to authenticate with PKAM: %d\n", ret);
    goto exit;
  }

  if ((ret = test_1_start_monitor(&monitor_conn)) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "test_1_start_monitor: %d\n", ret);
    goto exit;
  }

  if ((ret = test_2_send_notification(&atclient1)) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "test_3_send_notification: %d\n", ret);
    goto exit;
  }

  if ((ret = test_3_monitor_for_notification(&monitor_conn, &atclient2)) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "test_4_read_notification: %d\n", ret);
    goto exit;
  }

  if ((ret = test_4_re_pkam_auth_and_start_monitor(&monitor_conn)) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "test_4_re_pkam_auth_and_start_monitor: %d\n", ret);
    goto exit;
  }

  if ((ret = test_5_send_notification(&atclient1)) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "test_5_send_notification: %d\n", ret);
    goto exit;
  }

  if ((ret = test_6_monitor_for_notification(&monitor_conn, &atclient2)) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "test_6_monitor_for_notification: %d\n", ret);
    goto exit;
  }

  goto exit;
exit: {
  if ((ret = functional_tests_tear_down_sharedenckeys(&atclient1, ATKEY_SHAREDWITH)) != 0) {
    ret = 1;
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "Failed to tear down sharedenckeys: %d\n", ret);
  }
  atclient_atkeys_free(&atkeys_sharedby);
  atclient_atkeys_free(&atkeys_sharedwith);
  atclient_free(&atclient1);
  atclient_free(&atclient2);
  atclient_free(&monitor_conn);
  return ret;
}
}

static int monitor_pkam_auth(atclient *monitor_conn, const atclient_atkeys *atkeys, const char *atsign,
                             const size_t atsignlen) {
  int ret = 1;

  char *atserver_host = NULL;
  int atserver_port = -1;

  if ((ret = atclient_utils_find_atserver_address(ROOT_HOST, ROOT_PORT, atsign, &atserver_host, &atserver_port)) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atclient_utils_find_atserver_address: %d\n", ret);
    goto exit;
  }

  // log atserver_host and atserver_port
  // atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_INFO, "Host: %s\n", atserver_host);
  // atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_INFO, "Port: %d\n", atserver_port);

  if ((ret = atclient_monitor_pkam_authenticate(monitor_conn, atserver_host, atserver_port, atkeys, atsign)) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atclient_monitor_pkam_authenticate: %d\n", ret);
    goto exit;
  }

  ret = 0;
  goto exit;
exit: {
  free(atserver_host);
  return ret;
}
}

static int send_notification(atclient *atclient) {
  int ret = 1;

  atclient_notify_params params;
  atclient_notify_params_init(&params);

  atclient_atkey atkey;
  atclient_atkey_init(&atkey);

  if ((ret = atclient_atkey_create_sharedkey(&atkey, ATKEY_KEY, ATKEY_SHAREDBY, ATKEY_SHAREDWITH, ATKEY_NAMESPACE)) !=
      0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "Failed to create atkey: %d\n", ret);
    goto exit;
  }

  atclient_notify_params_create(&params, ATCLIENT_NOTIFY_OPERATION_UPDATE, &atkey, ATKEY_VALUE, true);
  params.notification_expiry = 1000;

  if ((ret = atclient_notify(atclient, &params, NULL)) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "Failed to notify: %d\n", ret);
    goto exit;
  }
exit: {
  atclient_atkey_free(&atkey);
  atclient_notify_params_free(&params);
  return ret;
}
}

static int monitor_for_notification(atclient *monitor_conn, atclient *atclient2) {
  int ret = 1;

  atclient_monitor_response message;
  atclient_monitor_message_init(&message);

  const int max_tries = 10;
  int tries = 1;

  while (tries <= max_tries) {
    if ((ret = atclient_monitor_read(monitor_conn, atclient2, &message, NULL)) != 0) {
      atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "Failed to read monitor message: %d\n", ret);
      tries++;
      continue;
    }

    if (!atclient_atnotification_decryptedvalue_is_initialized(&(message.notification))) {
      atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_INFO, "Decrypted value is not initialized\n");
      tries++;
      continue;
    }

    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_INFO, "Decrypted Value: %s\n",message.notification.decryptedvalue);

    // compare the decrypted value with the expected value
    if (strcmp(message.notification.decryptedvalue, ATKEY_VALUE) != 0) {
      atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "Decrypted value does not match expected value\n");
      tries++;
      continue;
    }

    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_INFO, "Tries: %d\n", tries);

    usleep(1000);

    ret = 0;
    goto exit;
  }

  atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "Failed to read monitor message after %d tries\n", max_tries);

  ret = 1;
  goto exit;
exit: {
  atclient_monitor_message_free(&message);
  return ret;
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

static int test_2_send_notification(atclient *atclient) {
  int ret = 1;

  atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_INFO, "test_2_send_notification Start\n");

  if ((ret = send_notification(atclient)) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "Failed to send notification: %d\n", ret);
    goto exit;
  }

  ret = 0;
  goto exit;
exit: {
  atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_INFO, "test_2_send_notification End: %d\n", ret);
  return ret;
}
}

static int test_3_monitor_for_notification(atclient *monitor_conn, atclient *atclient2) {
  int ret = 1;

  atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_INFO, "test_3_monitor_for_notification Start\n");

  if ((ret = monitor_for_notification(monitor_conn, atclient2)) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "Failed to monitor for notification: %d\n", ret);
    goto exit;
  }

  ret = 0;
  goto exit;
exit: {
  atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_INFO, "test_3_monitor_for_notification End: %d\n", ret);
  return ret;
}
}

static int test_4_re_pkam_auth_and_start_monitor(atclient *monitor_conn) {
  int ret = 1;

  atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_INFO, "test_4_re_pkam_auth_and_start_monitor Start\n");

  const char *atserver_host = strdup(monitor_conn->atserver_connection.host);
  const int atserver_port = monitor_conn->atserver_connection.port;

  if ((ret = atclient_monitor_pkam_authenticate(monitor_conn, atserver_host, atserver_port, &(monitor_conn->atkeys),
                                                monitor_conn->atsign)) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "Failed to authenticate with PKAM: %d\n", ret);
    goto exit;
  }

  if ((ret = atclient_monitor_start(monitor_conn, MONITOR_REGEX, strlen(MONITOR_REGEX))) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "Failed to start monitor: %d\n", ret);
    goto exit;
  }
  atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_INFO, "Started monitor\n");

  ret = 0;
  goto exit;
exit: {
  free(atserver_host);
  atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_INFO, "test_4_re_pkam_auth_and_start_monitor End: %d\n", ret);
  return ret;
}
}

static int test_5_send_notification(atclient *atclient) {
  int ret = 1;

  atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_INFO, "test_5_send_notification Start\n");

  if ((ret = send_notification(atclient)) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "Failed to send notification: %d\n", ret);
    goto exit;
  }

  ret = 0;
  goto exit;
exit: {
  atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_INFO, "test_5_send_notification End: %d\n", ret);
  return ret;
}
}

static int test_6_monitor_for_notification(atclient *monitor_conn, atclient *atclient2) {
  int ret = 1;

  atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_INFO, "test_6_monitor_for_notification Start\n");

  if ((ret = monitor_for_notification(monitor_conn, atclient2)) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "Failed to monitor for notification: %d\n", ret);
    goto exit;
  }

  ret = 0;
  goto exit;
exit: {
  atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_INFO, "test_6_monitor_for_notification End: %d\n", ret);
  return ret;
}
}