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
static int test_1_start_monitor(atclient *monitor_conn);
static int test_2_send_notification(atclient *atclient);
static int test_3_monitor_for_notification(atclient *monitor_conn, atclient *atclient2);

int main() {
  int ret = 1;

  atlogger_set_logging_level(ATLOGGER_LOGGING_LEVEL_DEBUG);

  atclient atclient1;
  atclient_init(&atclient1);

  atclient_atkeys atkeys_sharedby;
  atclient_atkeys_init(&atkeys_sharedby);

  atclient monitor_conn;
  atclient_init(&monitor_conn);

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

  if((ret = functional_tests_pkam_auth(&atclient2, &atkeys_sharedwith, ATKEY_SHAREDWITH, strlen(ATKEY_SHAREDWITH))) != 0) {
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

  goto exit;
exit: {
  if ((ret = functional_tests_tear_down_sharedenckeys(&atclient1, ATKEY_SHAREDWITH)) != 0) {
    ret = 1;
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "Failed to tear down sharedenckeys: %d\n", ret);
  }
  atclient_atkeys_free(&atkeys_sharedby);
  atclient_atkeys_free(&atkeys_sharedwith);
  atclient_free(&atclient1);
  atclient_free(&monitor_conn);
  return ret;
}
}

static int monitor_pkam_auth(atclient *monitor_conn, const atclient_atkeys *atkeys, const char *atsign,
                             const size_t atsignlen) {
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

  atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_INFO, "test_3_send_notification Start\n");

  atclient_notify_params params;
  atclient_notify_params_init(&params);

  atclient_atkey atkey;
  atclient_atkey_init(&atkey);

  if ((ret = atclient_atkey_create_sharedkey(&atkey, ATKEY_KEY, strlen(ATKEY_KEY), ATKEY_SHAREDBY,
                                             strlen(ATKEY_SHAREDBY), ATKEY_SHAREDWITH, strlen(ATKEY_SHAREDWITH),
                                             ATKEY_NAMESPACE, strlen(ATKEY_NAMESPACE))) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "Failed to create atkey: %d\n", ret);
    goto exit;
  }

  atclient_notify_params_create(&params, ATCLIENT_NOTIFY_OPERATION_UPDATE, &atkey, ATKEY_VALUE, true);

  if ((ret = atclient_notify(atclient, &params, NULL)) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "Failed to notify: %d\n", ret);
    goto exit;
  }

  goto exit;
exit: {
  atclient_notify_params_free(&params);
  atclient_atkey_free(&atkey);
  atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_INFO, "test_3_send_notification End: %d\n", ret);
  return ret;
}
}

static int test_3_monitor_for_notification(atclient *monitor_conn, atclient *atclient2) {
  int ret = 1;

  atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_INFO, "test_4_read_notification Start\n");

  atclient_monitor_message *message = NULL;

  int max_tries = 5;
  int tries = 1;

  while (tries < max_tries) {
    if ((ret = atclient_monitor_read(monitor_conn, atclient2, &message)) != 0) {
      atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "Failed to read monitor message: %d\n", ret);
      goto exit;
    }

    if (message == NULL) {
      atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_INFO,
                   "monitor message is NULL, when it is expected to be populated :(\n");
      tries++;
      continue;
    }

    if (!atclient_atnotification_decryptedvalue_is_initialized(&(message->notification))) {
      atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_INFO, "Decrypted value is not initialized\n");
      tries++;
      continue;
    }

    if (!atclient_atnotification_decryptedvaluelen_is_initialized(&(message->notification))) {
      atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_INFO, "Decrypted value length is not initialized\n");
      tries++;
      continue;
    }

    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_INFO, "Decrypted Value (%lu): %s\n",
                 (int)message->notification.decryptedvaluelen, message->notification.decryptedvalue);

    // compare the decrypted value with the expected value
    if (strcmp(message->notification.decryptedvalue, ATKEY_VALUE) != 0) {
      atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "Decrypted value does not match expected value\n");
      tries++;
      continue;
    }

    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_INFO, "Tries: %d\n", tries);

    ret = 0;
    goto exit;
  }

  atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "Failed to read monitor message after %d tries\n", max_tries);

  ret = 1;
  goto exit;
exit: {
  atclient_monitor_message_free(message);
  atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_INFO, "test_4_read_notification End: %d\n", ret);
  return ret;
}
}
