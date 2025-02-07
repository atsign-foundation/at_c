#include "atchops/uuid.h"
#include "atclient/notify.h"
#include "atclient/notify_params.h"
#include "functional_tests/config.h"
#include "functional_tests/helpers.h"

#include "atchops/aes.h"
#include "atchops/aes_ctr.h"
#include "atchops/base64.h"
#include "atchops/iv.h"
#include "atclient/constants.h"
#include "atclient/encryption_key_helpers.h"
#include <atclient/monitor.h>
#include <atlogger/atlogger.h>
#include <monitor.h>
#include <stdio.h>
#include <string.h>

#include "atnotification.h"

#include "psa/crypto_extra.h"

#define FROM_ATSIGN FIRST_ATSIGN
#define TO_ATSIGN SECOND_ATSIGN

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

#define TAG "test_atclient_monitor"

// decryption
static int test_1a_decrypt_notification(atclient *, atclient *);

// e2e test
static int test_2a_receive_notifications(atclient *, atclient *, atclient *);

int main() {
  int ret = 0;
  atlogger_set_logging_level(ATLOGGER_LOGGING_LEVEL_DEBUG);

  atclient from_client, to_client, worker_client;
  atclient_init(&from_client);
  atclient_init(&to_client);
  atclient_init(&worker_client);

  atclient_atkeys from_keys, to_keys;
  atclient_atkeys_init(&from_keys);
  atclient_atkeys_init(&to_keys);

  ret = functional_tests_set_up_atkeys(&from_keys, FROM_ATSIGN);
  if (ret != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "Failed to setup %s atkeys\n", FROM_ATSIGN);
    goto teardown;
  }

  ret = functional_tests_pkam_auth(&from_client, &from_keys, FROM_ATSIGN);
  if (ret != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "Failed to pkam auth %s\n", FROM_ATSIGN);
    goto teardown;
  }

  ret = functional_tests_set_up_atkeys(&to_keys, TO_ATSIGN);
  if (ret != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "Failed to setup %s atkeys\n", TO_ATSIGN);
    goto teardown;
  }

  ret = functional_tests_pkam_auth(&to_client, &to_keys, TO_ATSIGN);
  if (ret != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "Failed to pkam auth %s\n", TO_ATSIGN);
    goto teardown;
  }

  ret = functional_tests_pkam_auth(&worker_client, &to_keys, TO_ATSIGN);
  if (ret != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "Failed to do worker pkam auth %s\n", TO_ATSIGN);
    goto teardown;
  }

  ret += test_1a_decrypt_notification(&from_client, &to_client);
  ret += test_2a_receive_notifications(&from_client, &to_client, &worker_client);

  if (ret > 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "%d tests failed\n", ret);
  }

teardown:
  atclient_free(&from_client);
  atclient_free(&to_client);
  atclient_free(&worker_client);
  atclient_atkeys_free(&from_keys);
  atclient_atkeys_free(&to_keys);
  mbedtls_psa_crypto_free();
  return ret;
}

static int encrypt_notification(atclient *from_client, char *value, atclient_atnotification *notification) {
  int ret;
  const size_t sharedenckeysize = ATCHOPS_AES_256 / 8;
  unsigned char sharedenckey[sharedenckeysize];
  memset(sharedenckey, 0, sharedenckeysize);
  ret = atclient_get_shared_encryption_key_shared_by_me(from_client, TO_ATSIGN, sharedenckey);
  if (ret == ATCLIENT_ERR_AT0015_KEY_NOT_FOUND) {
    ret = atclient_create_shared_encryption_key_pair_for_me_and_other(from_client, TO_ATSIGN, sharedenckey);
    if (ret != 0) {
      atlogger_log(TAG " encrypt_notification", ATLOGGER_LOGGING_LEVEL_ERROR, "Failed to generate new sharedenckey\n");
      return 1;
    }
  } else if (ret != 0) {
    atlogger_log(TAG " encrypt_notification", ATLOGGER_LOGGING_LEVEL_ERROR, "Failed to get sharedenckey\n");
    return 1;
  }

  unsigned char iv[ATCHOPS_IV_BUFFER_SIZE];
  memset(iv, 0, ATCHOPS_IV_BUFFER_SIZE);
  ret = atchops_iv_generate(iv);
  if (ret != 0) {
    atlogger_log(TAG " encrypt_notification", ATLOGGER_LOGGING_LEVEL_ERROR, "Failed to generate iv for encryption\n");
    return 1;
  }

  const size_t ivbase64size = atchops_base64_encoded_size(ATCHOPS_IV_BUFFER_SIZE) + 1;
  char ivbase64[ivbase64size];
  memset(ivbase64, 0, sizeof(unsigned char) * ivbase64size);
  size_t ivbase64len = 0;

  ret = atchops_base64_encode(iv, ATCHOPS_IV_BUFFER_SIZE, ivbase64, ivbase64size, &ivbase64len);
  if (ret != 0) {
    atlogger_log(TAG " encrypt_notification", ATLOGGER_LOGGING_LEVEL_ERROR, "Failed to base64 encode iv\n");
    return 1;
  }

  const size_t ciphertextsize = atchops_aes_ctr_ciphertext_size(strlen(value));
  unsigned char ciphertext[ciphertextsize];
  memset(ciphertext, 0, sizeof(unsigned char) * ciphertextsize);
  size_t ciphertextlen = 0;

  ret = atchops_aes_ctr_encrypt(sharedenckey, ATCHOPS_AES_256, iv, (unsigned char *)value, strlen(value), ciphertext,
                                ciphertextsize, &ciphertextlen);
  if (ret != 0) {
    atlogger_log(TAG " encrypt_notification", ATLOGGER_LOGGING_LEVEL_ERROR, "Failed to encrypt notification value\n");
    return 1;
  }

  size_t value_size = atchops_base64_encoded_size(ciphertextlen) + 1;
  notification->value = malloc(sizeof(char) * value_size);
  if (notification->value == NULL) {
    atlogger_log(TAG " encrypt_notification", ATLOGGER_LOGGING_LEVEL_ERROR,
                 "Failed to allocate space for notification value\n");
    return 1;
  }
  memset(notification->value, 0, value_size);
  atclient_atnotification_value_set_initialized(notification, true);
  ret = atchops_base64_encode(ciphertext, ciphertextlen, notification->value, value_size, &value_size);
  if (ret != 0) {
    free(notification->value);
    atlogger_log(TAG " encrypt_notification", ATLOGGER_LOGGING_LEVEL_ERROR, "Failed to base64 encode iv\n");
    return 1;
  }
  notification->iv_nonce = malloc(sizeof(char) * (ivbase64len + 1));
  if (notification->iv_nonce == NULL) {
    free(notification->value);
    atlogger_log(TAG " encrypt_notification", ATLOGGER_LOGGING_LEVEL_ERROR,
                 "Failed to allocate notification iv_nonce\n");
    return 1;
  }
  memcpy(notification->iv_nonce, ivbase64, ivbase64len);
  notification->iv_nonce[ivbase64len] = 0;
  notification->is_encrypted = true;
  atclient_atnotification_iv_nonce_set_initialized(notification, true);
  atclient_atnotification_is_encrypted_set_initialized(notification, true);
  return 0;
}

// Note that in this test we are setting the bare minimum fields that should be required
// to successfully decrypt a notification
static int test_1a_decrypt_notification(atclient *from_client, atclient *to_client) {
  int ret;

  atclient_atnotification notification;
  atclient_atnotification_init(&notification);

  size_t from_len = strlen(FROM_ATSIGN);
  notification.from = malloc(sizeof(char) * (from_len + 1));
  if (notification.from == NULL) {
    atlogger_log(TAG " 1a", ATLOGGER_LOGGING_LEVEL_ERROR, "Failed to allocate notification.from\n");
    atclient_atnotification_free(&notification);
    return 1;
  }
  memcpy(notification.from, FROM_ATSIGN, from_len);
  notification.from[from_len] = 0;
  atclient_atnotification_from_set_initialized(&notification, true);

  ret = encrypt_notification(from_client, VERY_LONG_TEXT, &notification);
  if (ret != 0) {
    atlogger_log(TAG " 1a", ATLOGGER_LOGGING_LEVEL_ERROR, "Failed to encrypt notification\n");
    atclient_atnotification_free(&notification);
    return 1;
  }

  ret = decrypt_notification(to_client, &notification);
  if (ret != 0) {
    atlogger_log(TAG " 1a", ATLOGGER_LOGGING_LEVEL_ERROR, "Failed to decrypt notification\n");
    atclient_atnotification_free(&notification);
    return 1;
  }

  if (notification.decrypted_value == NULL) {
    atlogger_log(TAG " 1a", ATLOGGER_LOGGING_LEVEL_ERROR, "Notification decrypted value is NULL\n");
    atclient_atnotification_free(&notification);
    return 1;
  }

  size_t expected_len = strlen(VERY_LONG_TEXT);
  size_t actual_len = strlen(notification.decrypted_value);
  if (actual_len != expected_len) {
    atlogger_log(TAG " 1a", ATLOGGER_LOGGING_LEVEL_ERROR,
                 "Notification decrypted value length does not match expected length (expected: %zu, actual: %zu)\n",
                 expected_len, actual_len);
    atclient_atnotification_free(&notification);
    return 1;
  }

  if (strncmp(notification.decrypted_value, VERY_LONG_TEXT, expected_len) != 0) {
    atlogger_log(TAG " 1a", ATLOGGER_LOGGING_LEVEL_ERROR,
                 "Decrypted value doesn't match actual value\n"
                 "\t\texpected: '%s'\n\t\tactual: '%s'\n",
                 VERY_LONG_TEXT, notification.decrypted_value);
    atclient_atnotification_free(&notification);
    return 1;
  }

  atclient_atnotification_free(&notification);
  return 0;
}

static int send_notification(atclient *from_client, char *value, char *key, char *ns, char **id) {
  int ret;

  atclient_atkey atkey;
  atclient_atkey_init(&atkey);

  ret = atclient_atkey_set_shared_by(&atkey, FROM_ATSIGN);
  if (ret != 0) {
    atlogger_log(TAG " send_notification", ATLOGGER_LOGGING_LEVEL_ERROR, "Failed to set atkey shared_by\n");
    atclient_atkey_free(&atkey);
    return 1;
  }
  ret = atclient_atkey_set_shared_with(&atkey, TO_ATSIGN);
  if (ret != 0) {
    atlogger_log(TAG " send_notification", ATLOGGER_LOGGING_LEVEL_ERROR, "Failed to set atkey shared_with\n");
    atclient_atkey_free(&atkey);
    return 1;
  }
  ret = atclient_atkey_set_key(&atkey, key);
  if (ret != 0) {
    atlogger_log(TAG " send_notification", ATLOGGER_LOGGING_LEVEL_ERROR, "Failed to set atkey key\n");
    atclient_atkey_free(&atkey);
    return 1;
  }
  ret = atclient_atkey_set_namespace_str(&atkey, ns);
  if (ret != 0) {
    atlogger_log(TAG " send_notification", ATLOGGER_LOGGING_LEVEL_ERROR, "Failed to set atkey namespace\n");
    atclient_atkey_free(&atkey);
    return 1;
  }

  atclient_notify_params notify;
  atclient_notify_params_init(&notify);

  ret = atclient_notify_params_set_atkey(&notify, &atkey);
  if (ret != 0) {
    atlogger_log(TAG " send_notification", ATLOGGER_LOGGING_LEVEL_ERROR, "Failed to set notify atkey\n");
    atclient_notify_params_free(&notify);
    atclient_atkey_free(&atkey);
    return 1;
  }

  ret = atclient_notify_params_set_should_encrypt(&notify, true);
  if (ret != 0) {
    atlogger_log(TAG " send_notification", ATLOGGER_LOGGING_LEVEL_ERROR, "Failed to set notify should encrypt\n");
    atclient_notify_params_free(&notify);
    atclient_atkey_free(&atkey);
    return 1;
  }

  ret = atclient_notify_params_set_value(&notify, value);
  if (ret != 0) {
    atlogger_log(TAG " send_notification", ATLOGGER_LOGGING_LEVEL_ERROR, "Failed to set notify value\n");
    atclient_notify_params_free(&notify);
    atclient_atkey_free(&atkey);
    return 1;
  }

  ret = atclient_notify_params_set_operation(&notify, ATCLIENT_NOTIFY_OPERATION_UPDATE);
  if (ret != 0) {
    atlogger_log(TAG " send_notification", ATLOGGER_LOGGING_LEVEL_ERROR, "Failed to set notify operation\n");
    atclient_notify_params_free(&notify);
    atclient_atkey_free(&atkey);
    return 1;
  }

  ret = atclient_notify(from_client, &notify, id);

  atclient_notify_params_free(&notify);
  atclient_atkey_free(&atkey);
  return 0;
}

static int test_2a_receive_notifications(atclient *from_client, atclient *to_client, atclient *worker_client) {
  int ret;

  ret = atchops_uuid_init();
  if (ret != 0) {
    atlogger_log(TAG " 2a", ATLOGGER_LOGGING_LEVEL_ERROR, "Failed to init uuid\n");
    return 1;
  }
  char namespace[37];
  ret = atchops_uuid_generate(namespace, 37);
  if (ret != 0) {
    atlogger_log(TAG " 2a", ATLOGGER_LOGGING_LEVEL_ERROR, "Failed to generate uuid for namespace\n");
    return 1;
  }
  namespace[36] = 0;

  int timeout_seconds = 15;
  atclient_monitor_set_read_timeout(to_client, timeout_seconds * 1000); // 15 seconds

  ret = atclient_monitor_start(to_client, namespace);
  if (ret != 0) {
    atlogger_log(TAG " 2a", ATLOGGER_LOGGING_LEVEL_ERROR, "Failed to start monitor\n");
    return 1;
  }

  char *id1 = NULL;
  char *value1 = "fooval";
  size_t expected_value1_len = strlen(value1);
  char *key1 = "fookey";
  ret = send_notification(from_client, value1, key1, namespace, &id1);
  if (ret != 0) {
    atlogger_log(TAG " 2a", ATLOGGER_LOGGING_LEVEL_ERROR, "Failed first notify\n");
    return 1;
  }

  atclient_monitor_message message1;
  while (ret == 0) {
    atclient_monitor_message_init(&message1);
    ret = atclient_monitor_read(to_client, worker_client, &message1, NULL);
    if (ret == 0 && message1.type == ATCLIENT_MONITOR_MESSAGE_TYPE_NOTIFICATION &&
        strncmp(message1.notification->id, id1, strlen(message1.notification->id)) == 0) {
      // correct notification so check the values
      if (message1.notification->decrypted_value == NULL) {
        atlogger_log(TAG " 2a", ATLOGGER_LOGGING_LEVEL_ERROR, "Monitor 1 decrypted_value is NULL\n");
        free(id1);
        atclient_monitor_message_free(&message1);
        return 1;
      }
      size_t actual_len = strlen(message1.notification->decrypted_value);
      if (expected_value1_len != actual_len) {
        atlogger_log(TAG " 2a", ATLOGGER_LOGGING_LEVEL_ERROR,
                     "Monitor 1 decrypted_value has unexpected length (expected: %zu, actual: %zu)\n",
                     expected_value1_len, actual_len);
        free(id1);
        atclient_monitor_message_free(&message1);
        return 1;
      }
      if (strncmp(message1.notification->decrypted_value, value1, actual_len) != 0) {
        atlogger_log(TAG " 2a", ATLOGGER_LOGGING_LEVEL_ERROR,
                     "Monitor 1 decrypted_value has unexpected value\n\t\t"
                     "expected: '%s'\n\t\t"
                     "actual: '%s'\n",
                     value1, message1.notification->decrypted_value);
        free(id1);
        atclient_monitor_message_free(&message1);
        return 1;
      }
      atclient_monitor_message_free(&message1);
      break;
    }
    atclient_monitor_message_free(&message1);
  }
  free(id1);
  if (ret == ATCLIENT_SSL_TIMEOUT_EXITCODE) {
    atlogger_log(TAG " 2a", ATLOGGER_LOGGING_LEVEL_ERROR, "Monitor 1 timedout after %d seconds\n", timeout_seconds);
    return 1;
  } else if (ret != 0) {
    atlogger_log(TAG " 2a", ATLOGGER_LOGGING_LEVEL_ERROR, "Monitor 1 failed with code %d\n", ret);
    return 1;
  }

  char *id2 = NULL;
  char *value2 = "barval";
  size_t expected_value2_len = strlen(value2);
  char *key2 = "barkey";
  ret = send_notification(from_client, value2, key2, namespace, &id2);

  atclient_monitor_message message2;
  while (ret == 0) {
    atclient_monitor_message_init(&message2);
    ret = atclient_monitor_read(to_client, worker_client, &message2, NULL);
    if (ret == 0 && message2.type == ATCLIENT_MONITOR_MESSAGE_TYPE_NOTIFICATION &&
        strncmp(message2.notification->id, id2, strlen(id2)) == 0) {
      // correct notification so check the values
      if (message2.notification->decrypted_value == NULL) {
        atlogger_log(TAG " 2a", ATLOGGER_LOGGING_LEVEL_ERROR, "Monitor 2 decrypted_value is NULL\n");
        atclient_monitor_message_free(&message2);
        free(id2);
        return 1;
      }
      size_t actual_len = strlen(message2.notification->decrypted_value);
      if (expected_value2_len != actual_len) {
        atlogger_log(TAG " 2a", ATLOGGER_LOGGING_LEVEL_ERROR,
                     "Monitor 2 decrypted_value has unexpected length (expected: %zu, actual: %zu)\n",
                     expected_value2_len, actual_len);
        atclient_monitor_message_free(&message2);
        free(id2);
        return 1;
      }
      if (strncmp(message2.notification->decrypted_value, value2, actual_len) != 0) {
        atlogger_log(TAG " 2a", ATLOGGER_LOGGING_LEVEL_ERROR,
                     "Monitor 2 decrypted_value has unexpected value\n\t\t"
                     "expected: '%s'\n\t\t"
                     "actual: '%s'\n",
                     value2, message2.notification->decrypted_value);
        atclient_monitor_message_free(&message2);
        free(id2);
        return 1;
      }
      atclient_monitor_message_free(&message2);
      break;
    }
    atclient_monitor_message_free(&message2);
  }
  free(id2);
  if (ret == ATCLIENT_SSL_TIMEOUT_EXITCODE) {
    atlogger_log(TAG " 2a", ATLOGGER_LOGGING_LEVEL_ERROR, "Monitor 2 timedout after %d seconds\n", timeout_seconds);
    return 1;
  } else if (ret != 0) {
    atlogger_log(TAG " 2a", ATLOGGER_LOGGING_LEVEL_ERROR, "Monitor 2 failed with code %d\n", ret);
    return 1;
  }

  return 0;
}
