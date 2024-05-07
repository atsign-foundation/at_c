#include "functional_tests/config.h"
#include "functional_tests/helpers.h"
#include <atclient/atclient.h>
#include <atclient/notify.h>
#include <atclient/stringutils.h>
#include <atlogger/atlogger.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define TAG "test_atclient_notify"

#define ATKEY_KEY "test_atclient_notify"
#define ATKEY_NAMESPACE "functional_tests"
#define ATKEY_SHAREDBY FIRST_ATSIGN
#define ATKEY_SHAREDWITH SECOND_ATSIGN
#define ATKEY_VALUE "Test value 123 meow..."

#define ATNOTIFICATION_OPERATION ATCLIENT_NOTIFY_OPERATION_UPDATE

static int test_1_notify(atclient *atclient);

int main() {
  int ret = 1;

  atlogger_set_logging_level(ATLOGGER_LOGGING_LEVEL_DEBUG);

  atclient atclient;
  atclient_init(&atclient);

  if ((ret = functional_tests_pkam_auth(&atclient, ATKEY_SHAREDBY)) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "Failed to authenticate with PKAM: %d\n", ret);
    goto exit;
  }

  if ((ret = test_1_notify(&atclient)) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "Failed to test notify: %d\n", ret);
    goto exit;
  }

  goto exit;
exit: {
  atclient_free(&atclient);
  atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_INFO, "End (%d)\n", ret);
  return ret;
}
}

static int test_1_notify(atclient *atclient) {
  int ret = 1;

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

  atclient_notify_params_create(&params, ATNOTIFICATION_OPERATION, &atkey, ATKEY_VALUE);

  if((ret = atclient_notify(atclient, &params)) != 0)
  {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "Failed to notify: %d\n", ret);
    goto exit;
  }

  goto exit;

exit: {
  atclient_notify_params_free(&params);
  atclient_atkey_free(&atkey);
  return ret;
}
}
