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

#define TAG "test_atclient_notify"

#define ATKEY_KEY "test_atclient_notify"
#define ATKEY_NAMESPACE "functional_tests"
#define ATKEY_SHAREDBY FIRST_ATSIGN
#define ATKEY_SHAREDWITH SECOND_ATSIGN
#define ATKEY_VALUE "Test value 123 meow..."

#define VERY_LONG_TEXT                                                                                                 \
  "Lorem ipsum dolor sit amet, consectetur adipiscing elit. Praesent porttitor ligula eget sapien elementum aliquam. " \
  "Cras commodo ullamcorper velit, cursus pulvinar lorem euismod a. Mauris dapibus turpis elit, ac porta justo "       \
  "elementum in. In hac habitasse platea dictumst. Vivamus rutrum metus nec erat consequat, sed porta metus blandit. " \
  "Quisque pellentesque sapien quis odio vehicula tempus. Mauris vitae odio convallis, ullamcorper dui eget, iaculis " \
  "enim. Donec malesuada dolor massa, congue maximus nulla fermentum id. Maecenas eget nibh finibus diam fringilla "   \
  "posuere. Morbi non arcu ac neque tristique euismod at ac lectus.Vestibulum dolor libero, pharetra eget eleifend "   \
  "semper, lacinia sit amet sem. Cras tincidunt massa id mattis aliquet. Aenean porttitor a quam vitae pharetra. "     \
  "Vestibulum dui enim, vulputate vel pulvinar sit amet, fermentum vestibulum diam. Vestibulum condimentum quam "      \
  "purus, efficitur ultrices nulla blandit sed. Etiam aliquam eros felis, luctus malesuada ligula vestibulum vel. "    \
  "Nulla pellentesque ultricies urna, a imperdiet sapien. Mauris vel sagittis lectus. Maecenas ultricies, nulla id "   \
  "dapibus congue, erat nisl ornare nisl, ut condimentum enim est pulvinar odio. Sed posuere lorem vel semper "        \
  "dignissim. Sed in condimentum felis. Duis id commodo velit, id tempor odio. Donec eros libero, ultricies non "      \
  "lobortis eget, sollicitudin ut justo. Donec sollicitudin ante quam, vestibulum commodo massa suscipit nec. Nam "    \
  "accumsan eget arcu non ornare.Ut nec tincidunt diam. Sed sed est eget erat facilisis gravida. Suspendisse vitae "   \
  "odio vel eros aliquet porta. Nulla ut quam luctus, iaculis felis non, tristique arcu. Praesent hendrerit felis "    \
  "auctor auctor tristique. Cras viverra sed dui in dapibus. Class aptent taciti sociosqu ad litora torquent per "     \
  "conubia nostra, per inceptos himenaeos. Mauris sed dolor risus. Vivamus sagittis, magna hendrerit iaculis "         \
  "dapibus, magna urna congue ante, eleifend tincidunt dolor libero in magna. Proin vitae velit turpis. Pellentesque " \
  "et odio fermentum, tincidunt eros ut, fringilla leo. Aenean aliquam metus at aliquam placerat. Nunc quis ligula "   \
  "et odio tempor maximus ut eu metus. Mauris luctus purus rutrum, aliquam odio sit amet, vehicula dui. Nulla est "    \
  "tortor, volutpat ultricies metus vitae, rutrum eleifend orci. Class aptent taciti sociosqu ad litora torquent per " \
  "conubia nostra, per inceptos himenaeos.Aenean sodales feugiat enim, in tincidunt eros pharetra faucibus. Mauris "   \
  "sed dui in odio semper dignissim eget quis nulla. Duis eget tortor lorem. Duis non massa vestibulum, pellentesque " \
  "lectus iaculis, laoreet mi. Nulla aliquet purus sit amet nulla lobortis, et porttitor metus sodales. Nam in "       \
  "blandit arcu. Suspendisse vitae diam tortor. Nam bibendum in quam nec facilisis.Sed ante justo, tristique sit "     \
  "amet libero id, ornare egestas neque. Sed vulputate mi urna, id blandit nunc facilisis sit amet. Donec accumsan "   \
  "odio at mauris euismod porttitor. Quisque orci ipsum, blandit eu magna eu, imperdiet elementum felis porttitor."

#define ATNOTIFICATION_OPERATION ATCLIENT_NOTIFY_OPERATION_UPDATE

static int test_1_notify(atclient *atclient, char *notification_id);
static int test_2_notify_long_text(atclient *atclient, char *notification_id);

int main() {
  int ret = 1;

  atlogger_set_logging_level(ATLOGGER_LOGGING_LEVEL_DEBUG);

  atclient atclient1;
  atclient_init(&atclient1);

  atclient_atkeys atkeys;
  atclient_atkeys_init(&atkeys);

  char notification_id[37];
  memset(notification_id, 0, sizeof(char) * 37);

  if ((ret = functional_tests_set_up_atkeys(&atkeys, ATKEY_SHAREDBY, strlen(ATKEY_SHAREDBY))) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "Failed to set up atkeys: %d\n", ret);
    goto exit;
  }

  if ((ret = functional_tests_pkam_auth(&atclient1, &atkeys, ATKEY_SHAREDBY, strlen(ATKEY_SHAREDBY))) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "Failed to authenticate with PKAM: %d\n", ret);
    goto exit;
  }

  if ((ret = test_1_notify(&atclient1, notification_id)) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "Failed to test notify: %d\n", ret);
    goto exit;
  }

  if ((ret = test_2_notify_long_text(&atclient1, notification_id)) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "Failed to test notify long text: %d\n", ret);
    goto exit;
  }

  goto exit;
exit: {
  atclient_free(&atclient1);
  atclient_atkeys_free(&atkeys);
  atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_INFO, "End (%d)\n", ret);
  return ret;
}
}

static int test_1_notify(atclient *atclient, char *notification_id) {
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

  atclient_notify_params_create(&params, ATNOTIFICATION_OPERATION, &atkey, ATKEY_VALUE, true);

  if ((ret = atclient_notify(atclient, &params, NULL)) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "Failed to notify: %d\n", ret);
    goto exit;
  }

  goto exit;

exit: {
  if ((ret = functional_tests_tear_down_sharedenckeys(atclient, ATKEY_SHAREDWITH)) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "Failed to tear down sharedenckeys: %d\n", ret);
  }
  atclient_notify_params_free(&params);
  atclient_atkey_free(&atkey);
  return ret;
}
}

static int test_2_notify_long_text(atclient *atclient, char *notification_id) {
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

  atclient_notify_params_create(&params, ATNOTIFICATION_OPERATION, &atkey, VERY_LONG_TEXT, true);

  if ((ret = atclient_notify(atclient, &params, NULL)) != 0) {
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