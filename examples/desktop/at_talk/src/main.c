#include <atchops/aes.h>
#include <atchops/aesctr.h>
#include <atchops/base64.h>
#include <atchops/iv.h>
#include <atclient/atclient.h>
#include <atclient/atkeysfile.h>
#include <atclient/atsign.h>
#include <atclient/constants.h>
#include <atclient/encryption_key_helpers.h>
#include <atclient/monitor.h>
#include <atclient/notify.h>
#include <atlogger/atlogger.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define ROOT_HOST "root.atsign.org"
#define ROOT_PORT 64

#define ATKEYSFILE_PATH "/home/realvarx/.atsign/keys/@expensiveferret_key.atKeys"
#define ATSIGN "@expensiveferret"
#define RECIPIENT "@secondaryjackal"
#define ATKEY_NAME "attalk"
#define ATKEY_NAMESPACE "ai6bh"

#define TAG "at_talk"

static int attalk_get_both_shared_encryption_keys(atclient *ctx, const atclient_atsign *recipient,
                                                  char *enc_key_shared_by_me, char *enc_key_shared_by_other);

static int attalk_send_message(atclient *ctx, const atclient_atsign *recipient, char *enc_key_shared_by_me,
                               const char *message);

static int attalk_recv_message(atclient_monitor_message *message, char* enc_key_shared_by_other);

static int *monitor_handler(char *enc_key_shared_by_other);

static void *heartbeat_handler(void *monitor_connection);

int main(int argc, char **argv) {
  int ret = 0;

  atlogger_set_logging_level(ATLOGGER_LOGGING_LEVEL_INFO);

  // Init atclient
  atclient atclient;
  atclient_init(&atclient);

  // Init myatsign: the atsign that you'd like to use as a client
  // and assign it to the atclient "atsign" parameter
  atclient_atsign myatsign;
  ret = atclient_atsign_init(&myatsign, ATSIGN);
  if (ret != 0) {
    atclient_free(&atclient);
    return ret;
  }
  atclient.atsign = myatsign;

  // Init atkeysfile and read keys
  atclient_atkeysfile atkeysfile;
  atclient_atkeysfile_init(&atkeysfile);
  ret = atclient_atkeysfile_read(&atkeysfile, ATKEYSFILE_PATH);
  if (ret != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atclient_atkeys_file_read: %d\n", ret);
    atclient_free(&atclient);
    atclient_atkeysfile_free(&atkeysfile);
    return ret;
  }

  // Init atkeys and assign them to the atclient "atkeys" parameter
  atclient_atkeys atkeys;
  atclient_atkeys_init(&atkeys);
  ret = atclient_atkeys_populate_from_atkeysfile(&atkeys, atkeysfile);
  if (ret != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atclient_atkeys_populate_from_atkeysfile: %d\n", ret);
    goto exit1;
  }

  // Root connection and pkam auth
  atclient_connection root_conn;
  atclient_connection_init(&root_conn);
  atclient_connection_connect(&root_conn, "root.atsign.org", 64);

  ret = atclient_pkam_authenticate(&atclient, &root_conn, &atkeys, ATSIGN);
  if (ret != 0) {
    goto exit2;
  }

  // Init recipient's atsign
  atclient_atsign recipient;
  ret = atclient_atsign_init(&recipient, RECIPIENT);
  if (ret != 0) {
    goto exit2;
  }

  // Init variables and get the encryption keys

  char *enc_key_shared_by_me = malloc(45);
  char *enc_key_shared_by_other = malloc(45);
  ret = attalk_get_both_shared_encryption_keys(&atclient, &recipient, enc_key_shared_by_me, enc_key_shared_by_other);
  if (ret != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "attalk_get_both_shared_encryption_keys failed: %d\n", ret);
  }

  atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_INFO, "enc_key_shared_by_me: %s\n", enc_key_shared_by_me);
  atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_INFO, "enc_key_shared_by_other: %s\n", enc_key_shared_by_other);

  pthread_t tid;
  ret = pthread_create(&tid, NULL, monitor_handler, enc_key_shared_by_other);
  if (ret != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "Failed to create monitor_handler\n");
    return ret;
  }

  char *line = NULL;
  size_t len = 0;
  size_t read;

  while ((read = getline(&line, &len, stdin)) != -1) {

    if (line[read - 1] == '\n') {
      line[read - 1] = '\0';
    }

    ret = attalk_send_message(&atclient, &recipient, enc_key_shared_by_me, line);
  }

  return ret;

exit1 : {
  atclient_free(&atclient);
  atclient_atkeysfile_free(&atkeysfile);
  atclient_atkeys_free(&atkeys);
  return ret;
}
exit2 : {
  atclient_free(&atclient);
  atclient_atkeysfile_free(&atkeysfile);
  atclient_atkeys_free(&atkeys);
  atclient_connection_disconnect(&(atclient.secondary_connection));
  atclient_connection_free(&root_conn);
  return ret;
}
}

static int attalk_get_both_shared_encryption_keys(atclient *ctx, const atclient_atsign *recipient,
                                                  char *enc_key_shared_by_me, char *enc_key_shared_by_other) {
  int ret = -1;

  ret = atclient_get_shared_encryption_key_shared_by_me(ctx, recipient, enc_key_shared_by_me, true);
  if (ret != 0) {
    free(enc_key_shared_by_me);
    return ret;
  }

  ret = atclient_get_shared_encryption_key_shared_by_other(ctx, recipient, enc_key_shared_by_other);
  if (ret != 0) {
    free(enc_key_shared_by_me);
    free(enc_key_shared_by_other);
    return ret;
  }

  ret = 0;
  return ret;
}

static int *monitor_handler(char *enc_key_shared_by_other) {

  int ret = -1;

  // Init atclient
  atclient atclient;
  atclient_init(&atclient);

  // Init myatsign: the atsign that you'd like to use as a client
  // and assign it to the atclient "atsign" parameter
  atclient_atsign myatsign;
  ret = atclient_atsign_init(&myatsign, ATSIGN);
  if (ret != 0) {
    atclient_free(&atclient);
    return ret;
  }
  atclient.atsign = myatsign;

  // Init atkeysfile and read keys
  atclient_atkeysfile atkeysfile;
  atclient_atkeysfile_init(&atkeysfile);
  ret = atclient_atkeysfile_read(&atkeysfile, ATKEYSFILE_PATH);
  if (ret != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atclient_atkeys_file_read: %d\n", ret);
    atclient_free(&atclient);
    atclient_atkeysfile_free(&atkeysfile);
    return ret;
  }

  // Init atkeys and assign them to the atclient "atkeys" parameter
  atclient_atkeys atkeys;
  atclient_atkeys_init(&atkeys);
  ret = atclient_atkeys_populate_from_atkeysfile(&atkeys, atkeysfile);
  if (ret != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atclient_atkeys_populate_from_atkeysfile: %d\n", ret);
    return ret;
  }

  // Root connection and pkam auth
  atclient_connection root_conn;
  atclient_connection_init(&root_conn);
  atclient_connection_connect(&root_conn, "root.atsign.org", 64);

  ret = atclient_pkam_authenticate(&atclient, &root_conn, &atkeys, ATSIGN);
  if (ret != 0) {
    return ret;
  }

  // Init recipient's atsign
  atclient_atsign recipient;
  ret = atclient_atsign_init(&recipient, RECIPIENT);
  if (ret != 0) {
    return ret;
  }

  printf("Starting monitor\n");
  struct atclient monitor_ctx;
  atclient_monitor_init(&monitor_ctx);
  ret = atclient_start_monitor(&monitor_ctx, &root_conn, myatsign.atsign, &atkeys, ".*", strlen(".*"));
  if (ret != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "Monitor crashed\n");
    return ret;
  }
  printf("Monitor started!\n");

  printf("Starting heartbeat\n");
  pthread_t tid;
  ret = pthread_create(&tid, NULL, heartbeat_handler, &monitor_ctx);
  if (ret != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "Failed to create heartbeat_handler\n");
    return ret;
  }
  printf("Heartbeat started!\n");
  if (ret < 0) {
    return ret;
  }

  if ((ret = atclient_pkam_authenticate(&atclient, &root_conn, &atkeys, myatsign.atsign)) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "Failed to authenticate\n");
    return ret;
  }

  printf("Starting main monitor loop\n");
  atclient_monitor_message message;
  atclient_monitor_message_init(&message);
  while (true) {

    int mon_ret = atclient_monitor_read(&monitor_ctx, &message);
    if (mon_ret != 0) {
      atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "Failed to read monitor message: %d\n", mon_ret);
      continue;
    }

    switch (message.type) {
    case ATCLIENT_MONITOR_MESSAGE_TYPE_NONE:
      atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_DEBUG, "Message type: none\n");
      break;
    case ATCLIENT_MONITOR_MESSAGE_TYPE_NOTIFICATION:
      atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_DEBUG, "Message type: notification\n");
      atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_DEBUG, "Message id: %s\n", message.notification.id);

      if (strncmp(message.notification.id, "-1", strlen(message.notification.id))) {
        ret = attalk_recv_message(&message, enc_key_shared_by_other);
      }

      break;
    case ATCLIENT_MONITOR_MESSAGE_TYPE_DATA_RESPONSE:
      atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_DEBUG, "Message type: data\n");
      atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_DEBUG, "Message body: %s\n", message.data_response);
      break;
    case ATCLIENT_MONITOR_MESSAGE_TYPE_ERROR_RESPONSE:
      atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_DEBUG, "Message type: error\n");
      atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_DEBUG, "Message body: %s\n", message.error_response);
      break;
    }
    atclient_monitor_message_free(&message);
  }
  printf("Main monitor loop complete!\n");

  ret = 0;
  return ret;
}

static void *heartbeat_handler(void *monitor_connection) {
  atclient *connection = (atclient *)monitor_connection;
  atlogger_log("Heartbeat_handler", ATLOGGER_LOGGING_LEVEL_INFO, "Starting heartbeat_handler\n");
  while (true) {
    sleep(30);
    atlogger_log("Heartbeat_handler", ATLOGGER_LOGGING_LEVEL_DEBUG, "Sending heartbeat\n");
    atclient_send_heartbeat(connection);
  };
}

static int attalk_send_message(atclient *ctx, const atclient_atsign *recipient, char *enc_key_shared_by_me,
                               const char *message) {
  int ret = -1;
  atclient_atkey atkey;
  atclient_atkey_init(&atkey);

  atclient_atstr atkeystr;
  atclient_atstr_init(&atkeystr, ATCLIENT_ATKEY_FULL_LEN);

  if ((ret = atclient_atkey_create_sharedkey(&atkey, ATKEY_NAME, strlen(ATKEY_NAME), ctx->atsign.atsign,
                                             strlen(ctx->atsign.atsign), recipient->atsign, strlen(recipient->atsign),
                                             ATKEY_NAMESPACE, strlen(ATKEY_NAMESPACE))) != 0) {
    atclient_atkey_free(&atkey);
    atclient_atstr_free(&atkeystr);
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "Failed to create public key");
    return ret;
  }

  atclient_atkey_metadata_set_ccd(&atkey.metadata, true);

  if ((ret = atclient_atkey_to_string(&atkey, atkeystr.str, atkeystr.size, &atkeystr.len)) != 0) {
    atclient_atkey_free(&atkey);
    atclient_atstr_free(&atkeystr);

    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "Failed to convert to string");
    return ret;
  }

  atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_DEBUG, "atkeystr.str (%lu): \"%.*s\"\n", atkeystr.len, (int)atkeystr.len,
               atkeystr.str);

  atclient_notify_params notify_params;
  atclient_notify_params_init(&notify_params);

  const size_t ivlen = ATCHOPS_IV_BUFFER_SIZE;
  unsigned char iv[ATCHOPS_IV_BUFFER_SIZE];
  memset(iv, 0, sizeof(unsigned char) * ivlen);

  const size_t ivbase64size = 64;
  char ivbase64[ivbase64size];
  memset(ivbase64, 0, sizeof(char) * ivbase64size);
  size_t ivbase64len = 0;

  const size_t ciphertextsize = 4096;
  unsigned char ciphertext[ciphertextsize];
  memset(ciphertext, 0, sizeof(unsigned char) * ciphertextsize);
  size_t ciphertextlen = 0;

  const size_t ciphertextbase64size = 4096;
  char ciphertextbase64[ciphertextbase64size];
  memset(ciphertextbase64, 0, sizeof(char) * ciphertextbase64size);
  size_t ciphertextbase64len = 0;

  // generate IV
  ret = atchops_iv_generate(iv);
  if (ret != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atchops_iv_generate: %d\n", ret);
    return ret;
  }

  ret = atchops_base64_encode(iv, ATCHOPS_IV_BUFFER_SIZE, ivbase64, ivbase64size, &ivbase64len);
  if (ret != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atchops_base64_encode: %d\n", ret);
    return ret;
  }

  ret = atclient_atkey_metadata_set_ivnonce(&(atkey.metadata), ivbase64, ivbase64len);
  if (ret != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atclient_atkey_metadata_set_ivnonce: %d\n", ret);
    return ret;
  }

  // encrypt msg
  const size_t encryptionkeysize = ATCHOPS_AES_256 / 8;
  unsigned char encryptionkey[encryptionkeysize];
  memset(encryptionkey, 0, sizeof(unsigned char) * (ATCHOPS_AES_256 / 8));
  size_t encryptionkeylen = 0;
  ret = atchops_base64_decode(enc_key_shared_by_me, strlen(enc_key_shared_by_me), encryptionkey, encryptionkeysize,
                              &encryptionkeylen);
  if (ret != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atchops_base64_decode: %d\n", ret);
    return ret;
  }

  ret = atchops_aesctr_encrypt(encryptionkey, ATCHOPS_AES_256, iv, (unsigned char *)message, strlen(message),
                               ciphertext, ciphertextsize, &ciphertextlen);
  if (ret != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atchops_aesctr_encrypt: %d\n", ret);
    return ret;
  }

  ret = atchops_base64_encode(ciphertext, ciphertextlen, ciphertextbase64, ciphertextbase64size, &ciphertextbase64len);
  if (ret != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atchops_base64_encode: %d\n", ret);
    return ret;
  }

  notify_params.key = atkey;
  notify_params.value = ciphertextbase64;
  notify_params.operation = ATCLIENT_NOTIFY_OPERATION_UPDATE;

  if ((ret = atclient_notify(ctx, &notify_params, NULL)) != 0) {
    atclient_atkey_free(&atkey);
    atclient_atstr_free(&atkeystr);
    atclient_notify_params_free(&notify_params);

    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "Failed to notify");
    return ret;
  }

  atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_DEBUG, "Sent notification");
  // exit : { return ret; }
}

static int attalk_recv_message(atclient_monitor_message *message, char* enc_key_shared_by_other) {

  int ret = -1;
  char *valueraw = NULL;

  // Convert b64 enc_key to bytes
  const size_t encryptionkeysize = ATCHOPS_AES_256 / 8;
  unsigned char encryptionkey[encryptionkeysize];
  memset(encryptionkey, 0, sizeof(unsigned char) * (ATCHOPS_AES_256 / 8));
  size_t encryptionkeylen = 0;
  ret = atchops_base64_decode(enc_key_shared_by_other, strlen(enc_key_shared_by_other), encryptionkey,
                              encryptionkeysize, &encryptionkeylen);
  if (ret != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atchops_base64_decode: %d\n", ret);
    return ret;
  }

  unsigned char iv[ATCHOPS_IV_BUFFER_SIZE];

  const size_t valuelen = 1024;
  atclient_atstr value;
  atclient_atstr_init(&value, valuelen);

  // manage IV
  // if (atclient_atkey_metadata_is_ivnonce_initialized(&message->notification.key.metadata)) {
  //   size_t ivolen = 0;
    // ret = atchops_base64_decode((unsigned char *) message->notification.key.metadata.ivnonce.str,
    //                             message->notification.key.metadata.ivnonce.len, iv, ATCHOPS_IV_BUFFER_SIZE, &ivolen);
    // if (ret != 0) {
    //   atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atchops_base64_decode: %d\n", ret);
    //   return ret;
    // }

  //   if (ivolen != ATCHOPS_IV_BUFFER_SIZE) {
  //     ret = 1;
  //     atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "ivolen != ivlen (%d != %d)\n", ivolen, ATCHOPS_IV_BUFFER_SIZE);
  //     return ret;
  //   }
  // } else {
  //   // use legacy IV
  //   memset(iv, 0, sizeof(unsigned char) * ATCHOPS_IV_BUFFER_SIZE);
  // }

  const size_t valuerawsize = strlen(message->notification.value) * 4; // most likely enough space after base64 decode
  valueraw = malloc(sizeof(char) * valuerawsize);
  memset(valueraw, 0, sizeof(char) * valuerawsize);
  size_t valuerawlen = 0;

  ret = atchops_base64_decode((unsigned char *)message->notification.value, strlen(message->notification.value),
                              (unsigned char *)valueraw, valuerawsize, &valuerawlen);
  if (ret != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atchops_base64_decode: %d\n", ret);
    return ret;
  }

  // decrypt response data
  ret = atchops_aesctr_decrypt(encryptionkey, ATCHOPS_AES_256, iv, valueraw, valuerawlen, (unsigned char *)value.str,
                               value.size, &value.len);
  if (ret != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atchops_aesctr_decrypt: %d\n", ret);
    return ret;
  }

  // atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_INFO, "%s: %s\n", message->notification.key.sharedby.str, value.str);
}