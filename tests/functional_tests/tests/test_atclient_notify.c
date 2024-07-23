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

// 8012 bytes
#define VERY_LONG_TEXT                                                                                                 \
  "Lorem ipsum dolor sit amet, consectetur adipiscing elit. Sed elit mi, sagittis ac gravida id, scelerisque id "      \
  "nulla. Praesent gravida felis mollis dolor rhoncus facilisis. Etiam odio nibh, sagittis quis erat a, semper "       \
  "semper tellus. Cras enim mi, lacinia ac fermentum vel, tristique eu nisi. Nunc dictum sapien in ipsum accumsan "    \
  "congue. Class aptent taciti sociosqu ad litora torquent per conubia nostra, per inceptos himenaeos. Etiam arcu "    \
  "lorem, cursus id odio eget, sodales ultrices urna. Duis iaculis et ligula quis accumsan. Proin at velit "           \
  "consectetur, luctus nulla ac, varius diam. Donec sodales cursus tortor, nec fermentum justo egestas quis. Donec "   \
  "pellentesque nibh vitae odio dapibus tempor. Vestibulum eu consequat dolor. Etiam laoreet fringilla ligula, sed "   \
  "hendrerit dolor eleifend feugiat. Suspendisse sollicitudin ultrices lorem id varius. Duis consectetur iaculis ex, " \
  "et condimentum magna blandit a. Aliquam vitae ex tempus, gravida est in, ultrices nisl. Aenean sollicitudin "       \
  "auctor velit. Aenean accumsan felis non magna consectetur condimentum. Morbi dapibus volutpat convallis. "          \
  "Curabitur feugiat nisi nec augue rhoncus consectetur. Quisque efficitur lorem arcu, a finibus nisl dapibus "        \
  "maximus. Sed erat massa, bibendum sit amet luctus ac, dignissim sit amet tortor. Quisque fermentum efficitur "      \
  "laoreet. Sed porta vulputate erat, et pharetra nibh lacinia suscipit. Sed sit amet elit ac metus cursus luctus et " \
  "non leo. Proin nunc urna, finibus ut nisl vel, mollis laoreet eros. Morbi interdum auctor velit, ac hendrerit "     \
  "ante finibus in. Mauris ut arcu consectetur, imperdiet risus ac, porttitor neque. Morbi varius sed metus ac "       \
  "consequat. Praesent pharetra eros sit amet urna efficitur, a auctor dui interdum. Vestibulum congue diam orci, "    \
  "vel lacinia mi ultricies quis. Duis ac arcu velit. Aliquam vitae molestie libero, eu ultricies enim. Proin ac "     \
  "lacinia lacus. Morbi nisi lectus, viverra quis lorem vitae, congue volutpat mauris. Nullam accumsan massa nec "     \
  "faucibus mattis. Phasellus felis tellus, semper sed sollicitudin mollis, convallis sed nunc. Curabitur est ipsum, " \
  "placerat ac dolor quis, finibus gravida lectus. Mauris sit amet sem ut mauris euismod pulvinar. Nullam eget "       \
  "pulvinar leo. Aliquam vel rhoncus nibh. Curabitur et molestie erat. Vestibulum pretium laoreet risus eu faucibus. " \
  "Duis hendrerit tortor nec nibh suscipit tempus. Nunc condimentum lorem eros, et cursus orci pellentesque nec. "     \
  "Praesent aliquam nec velit elementum viverra. Integer sit amet lacinia eros. Aliquam elementum nec dolor vitae "    \
  "rutrum. Phasellus molestie dictum diam, at ullamcorper nisi mattis ac. Vestibulum ante ipsum primis in faucibus "   \
  "orci luctus et ultrices posuere cubilia curae; Sed sed laoreet lorem, suscipit pulvinar risus. Vivamus sed est "    \
  "mattis libero feugiat venenatis a sed neque. Mauris non iaculis nulla. Ut a dui mi. Aenean non finibus enim, a "    \
  "cursus ante. Donec venenatis sapien quis ullamcorper rutrum. Vivamus mollis maximus metus, quis semper eros "       \
  "dictum vel. Nulla facilisi. Aenean ullamcorper ullamcorper purus, ut varius erat mollis non. Maecenas aliquam "     \
  "imperdiet nunc a semper. Sed congue tincidunt enim a vulputate. Class aptent taciti sociosqu ad litora torquent "   \
  "per conubia nostra, per inceptos himenaeos. Nunc auctor molestie eros, ut facilisis elit ullamcorper sed. Morbi "   \
  "rhoncus scelerisque ultricies. Praesent hendrerit, lorem condimentum semper congue, erat erat convallis ante, ut "  \
  "vehicula massa elit et nisl. Nam pretium, est eu blandit varius, ante libero euismod ipsum, ut vulputate justo "    \
  "erat id nisl. Pellentesque condimentum nisl at nunc sollicitudin, sit amet commodo nisi aliquam. Vestibulum "       \
  "laoreet varius nibh vitae viverra. Sed a euismod magna. Nullam feugiat nibh vel lorem mattis fermentum. Mauris "    \
  "rhoncus sem et semper condimentum. Cras egestas turpis purus, et finibus tellus tincidunt vel. Aenean congue "      \
  "risus mauris, et molestie ipsum accumsan sit amet. Orci varius natoque penatibus et magnis dis parturient montes, " \
  "nascetur ridiculus mus. Maecenas eget risus nunc. Donec non arcu ligula. Morbi feugiat sem at nisl convallis "      \
  "lacinia. Etiam lobortis malesuada turpis non pellentesque. Cras tempor lorem sed commodo convallis. Mauris "        \
  "lobortis mauris libero, et pulvinar tortor pulvinar at. Nunc feugiat tortor non neque auctor, eget dignissim "      \
  "nulla fringilla. Sed ante leo, mattis vestibulum venenatis ac, iaculis aliquet metus. Cras lacinia tellus risus, "  \
  "id condimentum lacus elementum at. Quisque sit amet dolor non urna dapibus volutpat in ac erat. Integer at semper " \
  "arcu. Ut gravida pharetra ultricies. Fusce tincidunt nec diam sed convallis. Vestibulum ornare enim nec "           \
  "consectetur dignissim. Fusce sed laoreet sapien. Curabitur quis tellus vitae ipsum sagittis maximus. Vivamus ac "   \
  "nisl egestas, viverra libero vitae, tincidunt dui. Aenean urna velit, iaculis sed massa at, egestas semper "        \
  "tortor. Ut eu erat eu ex posuere fermentum ut eget orci. Sed vitae efficitur lacus. Sed id pellentesque leo. "      \
  "Quisque malesuada tellus sit amet venenatis fermentum. Maecenas ac mauris bibendum neque placerat ullamcorper. Ut " \
  "turpis sem, luctus sit amet semper ut, elementum nec nibh. Interdum et malesuada fames ac ante ipsum primis in "    \
  "faucibus. Nullam eleifend quam ut nunc interdum, nec consectetur orci imperdiet. Mauris et sollicitudin urna, "     \
  "vitae fermentum massa. Donec pretium a nunc et pharetra. Donec in justo eu erat pretium sodales. Vestibulum "       \
  "placerat finibus arcu, et ultrices orci viverra at. Ut sollicitudin nisl ut malesuada ullamcorper. Nullam sit "     \
  "amet nisi augue. Integer faucibus sodales ante id consequat. Praesent sed est tempor, bibendum arcu a, convallis "  \
  "nibh. Nam consectetur urna tincidunt orci tempus, quis tempus augue lacinia. Aliquam ac sem enim. Vestibulum "      \
  "eleifend felis enim, ac ullamcorper orci rutrum eu. In hac habitasse platea dictumst. Vivamus eu consectetur "      \
  "lorem. Morbi ornare ipsum a augue posuere efficitur. Praesent eget gravida sapien, quis semper mauris. Donec in "   \
  "leo condimentum, convallis nulla eu, rutrum nunc. Vestibulum sed ex faucibus, vehicula erat eu, egestas risus. Ut " \
  "vel convallis leo, ut vehicula ex. Fusce ultrices felis eget mattis accumsan. Suspendisse varius odio libero, nec " \
  "faucibus tellus pretium quis. Suspendisse pretium ullamcorper urna nec tristique. Interdum et malesuada fames ac "  \
  "ante ipsum primis in faucibus. Sed varius non ligula nec pharetra. Nunc volutpat magna a condimentum iaculis. "     \
  "Interdum et malesuada fames ac ante ipsum primis in faucibus. Aliquam elementum, purus vitae sollicitudin "         \
  "interdum, orci nisi tempus arcu, at convallis dui ex in lacus. Cras pretium vulputate diam, ut congue mi gravida "  \
  "at. Duis cursus nulla non interdum ultrices. Donec et mauris odio. Pellentesque ac condimentum turpis. Sed "        \
  "molestie mi lorem, id dictum mauris dignissim in. Donec vitae magna sed magna convallis tempus ultricies non "      \
  "velit. Nullam non ultrices ex. Aenean pharetra dignissim nunc a bibendum. Donec faucibus molestie egestas. Proin "  \
  "congue neque sit amet ex egestas, vitae blandit eros blandit. Aliquam vel accumsan nibh, eu consequat orci. "       \
  "Interdum et malesuada fames ac ante ipsum primis in faucibus. Donec pretium tristique nibh, ac tincidunt est "      \
  "blandit ut. In nulla est, imperdiet vitae dui at, aliquet convallis arcu. Curabitur feugiat consectetur orci, et "  \
  "interdum justo scelerisque non. Aliquam eget facilisis libero. Aliquam quam mi, pretium ut est non, sollicitudin "  \
  "pulvinar sapien. Pellentesque id rhoncus mi. Proin quis tellus vel magna volutpat sodales. Fusce elementum odio "   \
  "id accumsan facilisis. Maecenas eu scelerisque nisi, at fringilla nisl. Vivamus nunc tellus, sodales non metus "    \
  "quis, ornare porta massa. Maecenas feugiat quis elit at bibendum. Pellentesque aliquet nunc sed tincidunt "         \
  "malesuada. Duis volutpat aliquam lacus, eu cursus est aliquam eget. Morbi dictum erat ligula, et accumsan dolor "   \
  "tempus ac. Proin feugiat posuere odio sed tempus. Quisque a sagittis turpis. Etiam volutpat diam vel lorem "        \
  "bibendum venenatis. Vestibulum a purus mattis, pulvinar magna sed sed."

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

  atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_INFO, "test_1_notify Begin\n");

  atclient_notify_params params;
  atclient_notify_params_init(&params);

  atclient_atkey atkey;
  atclient_atkey_init(&atkey);

  if ((ret = atclient_atkey_create_shared_key(&atkey, ATKEY_KEY, ATKEY_SHAREDBY, ATKEY_SHAREDWITH, ATKEY_NAMESPACE)) !=
      0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "Failed to create atkey: %d\n", ret);
    goto exit;
  }

  if ((ret = atclient_notify_params_set_operation(&params, ATCLIENT_NOTIFY_OPERATION_UPDATE)) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "Failed to set operation: %d\n", ret);
    goto exit;
  }

  if ((ret = atclient_notify_params_set_atkey(&params, &atkey)) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "Failed to set atkey: %d\n", ret);
    goto exit;
  }

  if ((ret = atclient_notify_params_set_value(&params, ATKEY_VALUE)) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "Failed to set value: %d\n", ret);
    goto exit;
  }

  if ((ret = atclient_notify_params_set_should_encrypt(&params, true)) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "Failed to set should_encrypt: %d\n", ret);
    goto exit;
  }

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
  atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_INFO, "test_1_notify End (%d)\n", ret);
  return ret;
}
}

static int test_2_notify_long_text(atclient *atclient, char *notification_id) {
  int ret = 1;

  atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_INFO, "test_2_notify_long_text Begin\n");

  atclient_notify_params params;
  atclient_notify_params_init(&params);

  atclient_atkey atkey;
  atclient_atkey_init(&atkey);

  if ((ret = atclient_atkey_create_shared_key(&atkey, ATKEY_KEY, ATKEY_SHAREDBY, ATKEY_SHAREDWITH, ATKEY_NAMESPACE)) !=
      0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "Failed to create atkey: %d\n", ret);
    goto exit;
  }

  if((ret = atclient_notify_params_set_operation(&params, ATCLIENT_NOTIFY_OPERATION_UPDATE)) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "Failed to set operation: %d\n", ret);
    goto exit;
  }

  if((ret = atclient_notify_params_set_atkey(&params, &atkey)) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "Failed to set atkey: %d\n", ret);
    goto exit;
  }

  if((ret = atclient_notify_params_set_value(&params, VERY_LONG_TEXT)) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "Failed to set value: %d\n", ret);
    goto exit;
  }

  if((ret = atclient_notify_params_set_should_encrypt(&params, true)) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "Failed to set should_encrypt: %d\n", ret);
    goto exit;
  }

  if ((ret = atclient_notify(atclient, &params, NULL)) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "Failed to notify: %d\n", ret);
    goto exit;
  }

  goto exit;
exit: {
  atclient_notify_params_free(&params);
  atclient_atkey_free(&atkey);
  atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_INFO, "test_2_notify_long_text End (%d)\n", ret);
  return ret;
}
}