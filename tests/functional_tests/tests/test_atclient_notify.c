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

#define ATNOTIFICATION_OPERATION ATCLIENT_NOTIFY_OPERATION_UPDATE

static int test_1_notify(atclient *atclient, char *notification_id);

int main() {
  int ret = 1;

  atlogger_set_logging_level(ATLOGGER_LOGGING_LEVEL_DEBUG);

  atclient atclient1;
  atclient_init(&atclient1);

  char notification_id[37];
  memset(notification_id, 0, sizeof(char) * 37);

  if ((ret = functional_tests_pkam_auth(&atclient1, ATKEY_SHAREDBY)) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "Failed to authenticate with PKAM: %d\n", ret);
    goto exit;
  }

  if ((ret = test_1_notify(&atclient1, notification_id)) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "Failed to test notify: %d\n", ret);
    goto exit;
  }

  goto exit;
exit: {
  atclient_free(&atclient1);
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

  atclient_notify_params_create(&params, ATNOTIFICATION_OPERATION, &atkey, ATKEY_VALUE);

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

// static int test_2_receive_notification(atclient *atclient, char *notification_id) {
//   int ret = 1;

//   const size_t recvsize = 8192;
//   unsigned char recv[recvsize];
//   memset(recv, 0, recvsize);
//   size_t recvlen = 0;

//   if ((ret = atclient_connection_send(&atclient->secondary_connection, "notify:list\r\n", strlen("notify:list\r\n"),
//   recv,
//                                       recvsize, &recvlen)) != 0) {
//     atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atclient_connection_send: %d\n", ret);
//     return ret;
//   }

//   atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_DEBUG, "Received: %s\n", recv);

//   if (!atclient_stringutils_starts_with(recv, recvlen, "data:", strlen("data:"))) {
//     ret = 1;
//     atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "Received data does not start with 'data:'\n");
//     return ret;
//   }

//   char *data = recv + strlen("data:");
//   size_t datalen = recvlen - strlen("data:");

//   cJSON *root = cJSON_Parse(data);
//   if (root == NULL) {
//     ret = 1;
//     atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "Failed to parse JSON\n");
//     return ret;
//   }

//   // root is an array like [{"id": "..."}, {"id": "..."}, ...]
//   // find the id that matches *notification_id
//   cJSON *element = NULL;
//   cJSON_ArrayForEach(element, root) {
//     cJSON *id = cJSON_GetObjectItemCaseSensitive(element, "id");
//     if (id == NULL) {
//       continue;
//     }

//     if (strcmp(cJSON_GetStringValue(id), notification_id) == 0) {
//       ret = 0;
//       break;
//     }
//   }

//   const size_t sharedenckeysize = 32;
//   unsigned char sharedenckey[sharedenckeysize];
//   memset(sharedenckey, 0, sizeof(unsigned char) * sharedenckeysize);
//   size_t sharedenckeylen = 0;

//   const size_t sharedenckeybase64size = 45;
//   char sharedenckeybase64[sharedenckeybase64size];
//   memset(sharedenckeybase64, 0, sharedenckeybase64size);
//   size_t sharedenckeybase64len = 0;

//   const size_t encryptedvaluebase64size = 1024;
//   unsigned char encryptedvaluebase64[encryptedvaluebase64size];
//   memset(encryptedvaluebase64, 0, encryptedvaluebase64size);
//   size_t encryptedvaluebase64len = 0;

//   const size_t ivbase64size = 64;
//   unsigned char ivbase64[ivbase64size];
//   memset(ivbase64, 0, ivbase64size);
//   size_t ivbase64len = 0;

//   atclient_atsign other;
//   atclient_atsign_init(&other, ATKEY_SHAREDBY);

//   ret = atclient_get_shared_encryption_key_shared_by_other(atclient, &other, sharedenckeybase64);
//   if (ret != 0) {
//     atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "Failed to get shared encryption key: %d\n", ret);
//     return ret;
//   }

//   ret = atchops_base64_decode(sharedenckeybase64, strlen(sharedenckeybase64), sharedenckey, sharedenckeysize,
//                               &sharedenckeylen);

//   //   put "value" into encryptedvaluebase64
//   //   put "metaData.ivNonce" into ivbase64
//   cJSON *metaData = cJSON_GetObjectItemCaseSensitive(element, "metaData");
//   if (metaData == NULL) {
//     ret = 1;
//     atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "Failed to get metaData\n");
//     return ret;
//   }

//   cJSON *ivNonce = cJSON_GetObjectItemCaseSensitive(metaData, "ivNonce");
//   if (ivNonce == NULL) {
//     ret = 1;
//     atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "Failed to get ivNonce\n");
//     return ret;
//   }

//   ivbase64len = strlen(cJSON_GetStringValue(ivNonce));
//   memcpy(ivbase64, cJSON_GetStringValue(ivNonce), ivbase64len);

//   unsigned char iv[ATCHOPS_IV_BUFFER_SIZE];
//   memset(iv, 0, sizeof(unsigned char) * ATCHOPS_IV_BUFFER_SIZE);
//   size_t ivlen = 0;

//   ret = atchops_base64_decode(ivbase64, ivbase64len, iv, ATCHOPS_IV_BUFFER_SIZE, &ivlen);
//   if (ret != 0) {
//     atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "Failed to decode ivNonce: %d\n", ret);
//     return ret;
//   }
//   if (ivlen != ATCHOPS_IV_BUFFER_SIZE) {
//     atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "Could not decode ivNonce: %s\n", ivbase64);
//     return 1;
//   }

//   cJSON *value = cJSON_GetObjectItemCaseSensitive(element, "value");
//   if (value == NULL) {
//     ret = 1;
//     atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "Failed to get value\n");
//     return ret;
//   }

//   encryptedvaluebase64len = strlen(cJSON_GetStringValue(value));
//   memcpy(encryptedvaluebase64, cJSON_GetStringValue(value), encryptedvaluebase64len);

//   const size_t encryptedvaluesize = strlen(encryptedvaluebase64) * 4;
//   unsigned char encryptedvalue[encryptedvaluesize];
//   memset(encryptedvalue, 0, sizeof(unsigned char) * encryptedvaluesize);
//   size_t encryptedvaluelen = 0;

//   const size_t decryptedvaluesize = recvsize;
//   unsigned char decryptedvalue[decryptedvaluesize];
//   memset(decryptedvalue, 0, sizeof(unsigned char) * decryptedvaluesize);
//   size_t decryptedvaluelen = 0;

//   ret = atchops_aesctr_decrypt(sharedenckey, ATCHOPS_AES_256, iv, encryptedvalue, encryptedvaluelen, decryptedvalue,
//                                decryptedvaluesize, &decryptedvaluelen);
//   if (ret != 0) {
//     atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "Failed to decrypt value: %d\n", ret);
//     return ret;
//   }

//   atclient_atsign_free(&other);
//   cJSON_Delete(root);
// }
