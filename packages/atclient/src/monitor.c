#include "atclient/monitor.h"
#include "atclient/atclient.h"
#include "atclient/atclient_utils.h"
#include "atclient/atnotification.h"
#include "atclient/connection.h"
#include "atclient/constants.h"
#include "atclient/encryption_key_helpers.h"
#include "atclient/string_utils.h"
#include "atcommons/memory_util.h"
#include "atserver_message.h"
#include "monitor.h"
#include <atchops/aes.h>
#include <atchops/aes_ctr.h>
#include <atchops/base64.h>
#include <atchops/iv.h>
#include <atchops/platform.h>
#include <atchops/uuid.h>
#include <atlogger/atlogger.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define TAG "atclient_monitor"

#define max(a, b) (a > b ? a : b)

static void free_atserver_message(void *ptr);

void atclient_monitor_message_init(atclient_monitor_message *message) {
  memset(message, 0, sizeof(atclient_monitor_message));
  // ensure these fields are initalized as NULL on systems where NULL != 0
  message->atserver_message = NULL;
  message->data_response = NULL;
}

void atclient_monitor_message_free(atclient_monitor_message *message) {
  switch (message->type) {
  case ATCLIENT_MONITOR_MESSAGE_TYPE_NOTIFICATION:
  case ATCLIENT_MONITOR_ERROR_DECRYPT_NOTIFICATION:
  case ATCLIENT_MONITOR_ERROR_PARSE_NOTIFICATION:
    atclient_atnotification_free(message->notification);
  default:
    free_atserver_message(message->atserver_message);
    break;
  }
  message->atserver_message = NULL;
  message->data_response = NULL;
}

void atclient_monitor_init(atclient *monitor_conn) { atclient_init(monitor_conn); }
void atclient_monitor_free(atclient *monitor_conn) { atclient_free(monitor_conn); }

int atclient_monitor_pkam_authenticate(atclient *monitor_conn, const char *atsign, const atclient_atkeys *atkeys,
                                       atclient_authenticate_options *options) {
  int ret = 1;

  if ((ret = atclient_pkam_authenticate(monitor_conn, atsign, atkeys, options, NULL)) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "Failed to authenticate with PKAM\n");
    goto exit;
  }

  ret = 0;
  goto exit;
exit: { return ret; }
}

void atclient_monitor_set_read_timeout(atclient *monitor_conn, const int timeoutms) {
  atclient_set_read_timeout(monitor_conn, timeoutms);
}

int atclient_monitor_start(atclient *monitor_conn, const char *regex) {
  int ret = 1;

  size_t cmdsize = 0;
  char *cmd = NULL;

  const size_t regexlen = strlen(regex);

  // log building command... (Debug)
  // atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_DEBUG, "Building monitor command...\n");

  // 2. build cmd
  cmdsize += 7 + 2; // monitor + \r\n
  if (regexlen > 0) {
    cmdsize += regexlen + 1; // $regex + ' '
  }
  cmdsize += 1; // null terminator
  cmd = malloc(sizeof(char) * cmdsize);
  memset(cmd, 0, sizeof(char) * cmdsize);
  const size_t cmdlen = cmdsize - 1;

  if (regexlen > 0) {
    snprintf(cmd, cmdsize, "monitor %.*s\r\n", (int)regexlen, regex);
  } else {
    snprintf(cmd, cmdsize, "monitor\r\n");
  }

  monitor_conn->async_read = true;

  ret = atclient_connection_send(&monitor_conn->atserver_connection, (unsigned char *)cmd, cmdlen, NULL, 0, NULL);
  // 3. send monitor cmd
  if (ret != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "Failed to send monitor command: %d\n", ret);
    goto exit;
  }
  atlogger_fix_stdout_buffer(cmd, cmdsize);
  atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_DEBUG, "\t%sSENT: %s\"%.*s\"%s\n", BBLK, HCYN, (int)strlen(cmd), cmd,
               ATCLIENT_RESET);

  ret = 0;
  goto exit;
exit: {
  free(cmd);
  return ret;
}
}

static void free_atserver_message(void *ptr) {
  if (ptr != NULL) {
    atserver_message_free((struct atserver_message *)ptr);
    free(ptr);
  }
}

int atclient_monitor_read(atclient *monitor_conn, atclient *atclient, atclient_monitor_message *message,
                          atclient_monitor_hooks *hooks) {

  unsigned char *buffer = NULL;
  size_t buffer_len;

  int ret = atclient_tls_socket_read(&monitor_conn->atserver_connection._socket, &buffer, &buffer_len,
                                     atclient_socket_read_until_char('\n'));

  if (ret == ATCLIENT_SSL_TIMEOUT_EXITCODE) {
    // treat a timeout as empty message, non error
    message->type = ATCLIENT_MONITOR_MESSAGE_TYPE_EMPTY;
    free(buffer);
    return 0;
  } else if (ret != 0) { // you should reconnect...
    message->type = ATCLIENT_MONITOR_ERROR_READ;
    message->error_read.error_code = ret;
    free(buffer);
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_DEBUG, "Error: monitor exited with code %d\n", ret);
    return ret;
  }

  message->atserver_message = malloc(sizeof(struct atserver_message));
  if (message->atserver_message == NULL) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_DEBUG, "Failed to allocate message->atserver_message\n");
    free(buffer);
    return 1;
  }

  { // temp_message scope
    struct atserver_message temp_message = atserver_message_parse((char *)buffer, buffer_len);
    if (temp_message.len == 0) {
      atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_DEBUG, "Failed to parse atserver message\n");
      free(buffer);
      free(message->atserver_message);
      return 1;
    }
    memcpy(message->atserver_message, &temp_message, sizeof(struct atserver_message));
  }
  // no longer need to free buffer, memory is owned by message->atserver_message

  atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_DEBUG, "\t%sRECV: %s\"%.*s\"%s\n", BMAG, HMAG, buffer_len, buffer,
               ATCLIENT_RESET);

  ret = populate_monitor_message(message);
  if (ret != 0) {
    free_atserver_message(message->atserver_message);
    return ret;
  } else if (message->type != ATCLIENT_MONITOR_MESSAGE_TYPE_NOTIFICATION) {
    return 0;
  }

  // Can only be a success notification at this point, time to decrypt
  if (hooks != NULL && hooks->pre_decrypt_notification != NULL) {
    ret = hooks->pre_decrypt_notification();
    if (ret != 0) {
      message->type = ATCLIENT_MONITOR_ERROR_DECRYPT_NOTIFICATION;
      atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "Failed to run pre_decrypt_notification hook\n");
      free_atserver_message(message->atserver_message);
      return ret;
    }
  }

  ret = decrypt_notification(atclient, message->notification);
  if (hooks != NULL && hooks->post_decrypt_notification != NULL) {
    ret = hooks->post_decrypt_notification(ret);
    if (ret != 0) {
      message->type = ATCLIENT_MONITOR_ERROR_DECRYPT_NOTIFICATION;
      atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "Failed to run post_decrypt_notification hook\n");
      free_atserver_message(message->atserver_message);
      return ret;
    }
  }

  if (ret != 0) {
    message->type = ATCLIENT_MONITOR_ERROR_DECRYPT_NOTIFICATION;
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "Failed to decrypt notification");
    free_atserver_message(message->atserver_message);
  }
  return ret;
}

bool atclient_monitor_is_connected(atclient *monitor_conn) {
  return atclient_connection_is_connected(&monitor_conn->atserver_connection);
}

int populate_monitor_message(atclient_monitor_message *message) {
  struct atserver_message *atserver_message = message->atserver_message;
  const char *token = atserver_message_get_token(*atserver_message);
  size_t token_len = atserver_message->token_len;
  if (token == NULL || token_len == 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atserver_message has no token prefix\n");
    return 1;
  }

  switch (token_len) {
  case 5:
    if (strncmp(token, "data:", 5) == 0) {
      return populate_monitor_data_message(message);
    }
    break;
  case 6:
    if (strncmp(token, "error:", 6) == 0) {
      return populate_monitor_error_message(message);
    }
    break;
  case 13:
    if (strncmp(token, "notification:", 13) == 0) {
      return populate_monitor_notification_message(message);
    }
    break;
  }
  atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "Unknown token type: %.*s\n", token_len, token);
  return 2;
}

int populate_monitor_data_message(atclient_monitor_message *message) {
  struct atserver_message *atserver_message = message->atserver_message;
  char *body = atserver_message_get_body(*atserver_message);
  if (body == NULL) {
    message->type = ATCLIENT_MONITOR_MESSAGE_TYPE_EMPTY;
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "Empty body for atserver data response\n");
    return 1;
  }
  message->type = ATCLIENT_MONITOR_MESSAGE_TYPE_DATA_RESPONSE;
  message->data_response = body;
  return 0;
}

int populate_monitor_error_message(atclient_monitor_message *message) {
  struct atserver_message *atserver_message = message->atserver_message;
  char *body = atserver_message_get_body(*atserver_message);
  if (body == NULL) {
    message->type = ATCLIENT_MONITOR_MESSAGE_TYPE_EMPTY;
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "Empty body for atserver error response\n");
    return 1;
  }
  message->type = ATCLIENT_MONITOR_MESSAGE_TYPE_ERROR_RESPONSE;
  message->error_response = body;
  return 0;
}

int populate_monitor_notification_message(atclient_monitor_message *message) {
  struct atserver_message *atserver_message = message->atserver_message;

  char *body = atserver_message_get_body(*atserver_message);
  if (body == NULL) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "Empty body for atserver error response\n");
    return 1;
  }
  message->notification = malloc(sizeof(atclient_atnotification));
  if (message->notification == NULL) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "Failed to allocate memory for notification\n");
    return 2;
  }

  int ret = atclient_atnotification_from_json_str(message->notification, body);
  if (ret != 0) {
    message->type = ATCLIENT_MONITOR_ERROR_PARSE_NOTIFICATION;
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "Failed to parse the notification\n");
  } else {
    message->type = ATCLIENT_MONITOR_MESSAGE_TYPE_NOTIFICATION;
  }

  return ret;
}

// after calling `parse_notification`, the *notification struct will be partially filled, all that is left to do is
// decrypt notification->value and put the result in notification->decrypted_value
int decrypt_notification(atclient *atclient, atclient_atnotification *notification) {
  int ret = 1;

  if (atclient == NULL) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atclient is NULL\n");
    return ret;
  }

  if (notification == NULL) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "notification is NULL\n");
    return ret;
  }

  struct atcommons_memlist memlist = atcommons_memlist_create(5);
  if (memlist.len == 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "Failed to create memlist\n");
    return ret;
  }
  char *from_atsign = NULL;

  unsigned char *decryptedvaluetemp = NULL;

  // holds encrypted value but in raw bytes (after base64 decode operation)
  const size_t ciphertextsize = (strlen(notification->value) + 15) / 16 * 16;
  unsigned char ciphertext[ciphertextsize];
  memset(ciphertext, 0, sizeof(unsigned char) * ciphertextsize);
  size_t ciphertextlen = 0;

  // holds shared encryption key in raw bytes (after base64 decode operation)
  const size_t sharedenckeysize = ATCHOPS_AES_256 / 8;
  unsigned char sharedenckey[sharedenckeysize];

  // temporarily holds the shared encryption key in base64
  const size_t sharedenckeybase64size = atchops_base64_encoded_size(sharedenckeysize);
  unsigned char sharedenckeybase64[sharedenckeybase64size];
  memset(sharedenckeybase64, 0, sizeof(unsigned char) * sharedenckeybase64size);

  unsigned char iv[ATCHOPS_IV_BUFFER_SIZE];

  // 1. make sure everything we need is there

  // 1a. check if value is initialized
  if (!atclient_atnotification_is_value_initialized(notification)) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "Value is not initialized. Nothing was found to decrypt.\n");
    goto exit;
  }

  if (!atclient_atnotification_is_from_initialized(notification) && notification->from != NULL) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "From field is not initialized\n");
    goto exit;
  }

  // 1b. some warnings
  if (!atclient_atnotification_is_is_encrypted_initialized(notification)) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_WARN,
                 "is_encrypted field was found to be uninitialized, we don't know for sure if we're decrypting "
                 "something that's even encrypted.\n");
  } else {
    if (!notification->is_encrypted) {
      atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_WARN,
                   "is_encrypted is false, we may be trying to decrypt some unencrypted plain text.\n");
    }
  }

  // 1c. get atsign with @
  if ((ret = atclient_string_utils_atsign_with_at(notification->from, &from_atsign)) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "Failed to get atsign with @\n");
    goto exit;
  }
  ret = atcommons_memlist_add(&memlist, from_atsign, true, NULL);
  if (ret != 0) {
    free(from_atsign);
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "Failed to add from_atsign to memlist\n");
    goto exit;
  }

  // 2. get iv
  if (atclient_atnotification_is_iv_nonce_initialized(notification) &&
      !atclient_string_utils_starts_with(notification->iv_nonce, "null")) {
    size_t ivlen;
    ret = atchops_base64_decode(notification->iv_nonce, strlen(notification->iv_nonce), iv, ATCHOPS_IV_BUFFER_SIZE,
                                &ivlen);
    if (ret != 0) {
      atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "Failed to decode iv\n");
      goto exit;
    }

    if (ivlen != ATCHOPS_IV_BUFFER_SIZE) {
      ret = 1;
      atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "Invalid iv length was decoded. Expected %d but got %d\n",
                   ATCHOPS_IV_BUFFER_SIZE, ivlen);
      goto exit;
    }
  } else {
    memset(iv, 0, sizeof(unsigned char) * ATCHOPS_IV_BUFFER_SIZE); // legacy IV
  }

  // 3. get shared encryption key to decrypt
  if ((ret = atclient_get_shared_encryption_key_shared_by_other(atclient, from_atsign, sharedenckey)) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "Failed to get shared encryption key\n");
    goto exit;
  }

  // 4. decrypt value
  ret = atchops_base64_decode(notification->value, strlen(notification->value), ciphertext, ciphertextsize,
                              &ciphertextlen);
  if (ret != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "Failed to decode value\n");
    goto exit;
  }

  const size_t decryptedvaluetempsize = ciphertextlen + 1;
  decryptedvaluetemp = malloc(sizeof(unsigned char) * decryptedvaluetempsize);
  if (decryptedvaluetemp == NULL) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "Failed to allocate memory for decrypted value\n");
    goto exit;
  }
  ret = atcommons_memlist_add(&memlist, decryptedvaluetemp, true, NULL);
  if (ret != 0) {
    free(decryptedvaluetemp);
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "Failed to add decrypted value temp buffer to memlist\n");
    goto exit;
  }
  memset(decryptedvaluetemp, 0, sizeof(unsigned char) * decryptedvaluetempsize);
  size_t decryptedvaluetemplen = 0;

  ret = atchops_aes_ctr_decrypt(sharedenckey, ATCHOPS_AES_256, iv, ciphertext, ciphertextlen, decryptedvaluetemp,
                                decryptedvaluetempsize, &decryptedvaluetemplen);
  if (ret != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "Failed to decrypt value\n");
    goto exit;
  }

  // 5. set decrypted value
  atclient_atnotification_set_decrypted_value(notification, (const char *)decryptedvaluetemp);

  ret = 0;
  goto exit;
exit: {
  if (ret == 0) {
    atcommons_memlist_success_free(&memlist);
  } else {
    atcommons_memlist_failure_free(&memlist);
  }
  return ret;
}
}
