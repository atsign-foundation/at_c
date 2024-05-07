#include "atclient/monitor.h"
#include "atclient/atclient.h"
#include "atclient/connection.h"
#include "atclient/constants.h"
#include "cJSON.h"
#include <atchops/uuid.h>
#include <atlogger/atlogger.h>
#include <mbedtls/threading.h>
#include <stdlib.h>
#include <string.h>
#include <sys/time.h>
#include <unistd.h>

#define TAG "atclient_monitor"

static int parse_message(char *original, char **message_type, char **message_body);
static int parse_notification(atclient_atnotification *notification, const char *messagebody);

void atclient_atnotification_init(atclient_atnotification *notification) {
  memset(notification, 0, sizeof(atclient_atnotification));
}

void atclient_atnotification_free(atclient_atnotification *notification) {
  if (atclient_atnotification_id_is_initialized(notification)) {
    atclient_atnotification_free_id(notification);
  }
  if (atclient_atnotification_from_is_initialized(notification)) {
    atclient_atnotification_free_from(notification);
  }
  if (atclient_atnotification_to_is_initialized(notification)) {
    atclient_atnotification_free_to(notification);
  }
  if (atclient_atnotification_key_is_initialized(notification)) {
    atclient_atnotification_free_key(notification);
  }
  if (atclient_atnotification_value_is_initialized(notification)) {
    atclient_atnotification_free_value(notification);
  }
  if (atclient_atnotification_operation_is_initialized(notification)) {
    atclient_atnotification_free_operation(notification);
  }
  if (atclient_atnotification_epochMillis_is_initialized(notification)) {
    atclient_atnotification_free_epochMillis(notification);
  }
  if (atclient_atnotification_messageType_is_initialized(notification)) {
    atclient_atnotification_free_messageType(notification);
  }
  if (atclient_atnotification_isEncrypted_is_initialized(notification)) {
    atclient_atnotification_free_isEncrypted(notification);
  }
}

bool atclient_atnotification_id_is_initialized(const atclient_atnotification *notification) {
  return (notification->initalizedfields[0] & ATCLIENT_ATNOTIFICATION_INITIALIZED);
}

bool atclient_atnotification_from_is_initialized(const atclient_atnotification *notification) {
  return (notification->initalizedfields[0] & ATCLIENT_ATNOTIFICATION_FROM_INITIALIZED);
}

bool atclient_atnotification_to_is_initialized(const atclient_atnotification *notification) {
  return (notification->initalizedfields[0] & ATCLIENT_ATNOTIFICATION_TO_INITIALIZED);
}

bool atclient_atnotification_key_is_initialized(const atclient_atnotification *notification) {
  return (notification->initalizedfields[0] & ATCLIENT_ATNOTIFICATION_KEY_INITIALIZED);
}

bool atclient_atnotification_value_is_initialized(const atclient_atnotification *notification) {
  return (notification->initalizedfields[0] & ATCLIENT_ATNOTIFICATION_VALUE_INITIALIZED);
}

bool atclient_atnotification_operation_is_initialized(const atclient_atnotification *notification) {
  return (notification->initalizedfields[0] & ATCLIENT_ATNOTIFICATION_OPERATION_INITIALIZED);
}

bool atclient_atnotification_epochMillis_is_initialized(const atclient_atnotification *notification) {
  return (notification->initalizedfields[0] & ATCLIENT_ATNOTIFICATION_EPOCHMILLIS_INITIALIZED);
}

bool atclient_atnotification_messageType_is_initialized(const atclient_atnotification *notification) {
  return (notification->initalizedfields[0] & ATCLIENT_ATNOTIFICATION_MESSAGETYPE_INITIALIZED);
}

bool atclient_atnotification_isEncrypted_is_initialized(const atclient_atnotification *notification) {
  return (notification->initalizedfields[1] & ATCLIENT_ATNOTIFICATION_ISENCRYPTED_INITIALIZED);
}

bool atclient_atnotification_encKeyName_is_initialized(const atclient_atnotification *notification)
{
  return (notification->initalizedfields[1] & ATCLIENT_ATNOTIFICATION_ENCKEYNAME_INITIALIZED);
}

bool atclient_atnotification_encAlgo_is_initialized(const atclient_atnotification *notification)
{
  return (notification->initalizedfields[1] & ATCLIENT_ATNOTIFICATION_ENCALGO_INITIALIZED);
}

bool atclient_atnotification_ivNonce_is_initialized(const atclient_atnotification *notification)
{
  return (notification->initalizedfields[1] & ATCLIENT_ATNOTIFICATION_IVNONCE_INITIALIZED);
}

bool atclient_atnotification_skeEncKeyName_is_initialized(const atclient_atnotification *notification)
{
  return (notification->initalizedfields[1] & ATCLIENT_ATNOTIFICATION_SKEENCKEYNAME_INITIALIZED);
}

bool atclient_atnotification_skeEncAlgo_is_initialized(const atclient_atnotification *notification)
{
  return (notification->initalizedfields[1] & ATCLIENT_ATNOTIFICATION_SKEENCALGO_INITIALIZED);
}


void atclient_atnotification_id_set_initialized(atclient_atnotification *notification, bool initialized) {
  if (initialized) {
    notification->initalizedfields[0] |= ATCLIENT_ATNOTIFICATION_ID_INITIALIZED;
  } else {
    notification->initalizedfields[0] &= ~ATCLIENT_ATNOTIFICATION_ID_INITIALIZED;
  }
}

void atclient_atnotification_from_set_initialized(atclient_atnotification *notification, bool initialized) {
  if (initialized) {
    notification->initalizedfields[0] |= ATCLIENT_ATNOTIFICATION_FROM_INITIALIZED;
  } else {
    notification->initalizedfields[0] &= ~ATCLIENT_ATNOTIFICATION_FROM_INITIALIZED;
  }
}

void atclient_atnotification_to_set_initialized(atclient_atnotification *notification, bool initialized) {
  if (initialized) {
    notification->initalizedfields[0] |= ATCLIENT_ATNOTIFICATION_TO_INITIALIZED;
  } else {
    notification->initalizedfields[0] &= ~ATCLIENT_ATNOTIFICATION_TO_INITIALIZED;
  }
}

void atclient_atnotification_key_set_initialized(atclient_atnotification *notification, bool initialized) {
  if (initialized) {
    notification->initalizedfields[0] |= ATCLIENT_ATNOTIFICATION_KEY_INITIALIZED;
  } else {
    notification->initalizedfields[0] &= ~ATCLIENT_ATNOTIFICATION_KEY_INITIALIZED;
  }
}

void atclient_atnotification_value_set_initialized(atclient_atnotification *notification, bool initialized) {
  if (initialized) {
    notification->initalizedfields[0] |= ATCLIENT_ATNOTIFICATION_VALUE_INITIALIZED;
  } else {
    notification->initalizedfields[0] &= ~ATCLIENT_ATNOTIFICATION_VALUE_INITIALIZED;
  }
}

void atclient_atnotification_operation_set_initialized(atclient_atnotification *notification, bool initialized) {
  if (initialized) {
    notification->initalizedfields[0] |= ATCLIENT_ATNOTIFICATION_OPERATION_INITIALIZED;
  } else {
    notification->initalizedfields[0] &= ~ATCLIENT_ATNOTIFICATION_OPERATION_INITIALIZED;
  }
}

void atclient_atnotification_epochMillis_set_initialized(atclient_atnotification *notification, bool initialized) {
  if (initialized) {
    notification->initalizedfields[0] |= ATCLIENT_ATNOTIFICATION_EPOCHMILLIS_INITIALIZED;
  } else {
    notification->initalizedfields[0] &= ~ATCLIENT_ATNOTIFICATION_EPOCHMILLIS_INITIALIZED;
  }
}

void atclient_atnotification_messageType_set_initialized(atclient_atnotification *notification, bool initialized) {
  if (initialized) {
    notification->initalizedfields[0] |= ATCLIENT_ATNOTIFICATION_MESSAGETYPE_INITIALIZED;
  } else {
    notification->initalizedfields[0] &= ~ATCLIENT_ATNOTIFICATION_MESSAGETYPE_INITIALIZED;
  }
}

void atclient_atnotification_isEncrypted_set_initialized(atclient_atnotification *notification, bool initialized) {
  if (initialized) {
    notification->initalizedfields[1] |= ATCLIENT_ATNOTIFICATION_ISENCRYPTED_INITIALIZED;
  } else {
    notification->initalizedfields[1] &= ~ATCLIENT_ATNOTIFICATION_ISENCRYPTED_INITIALIZED;
  }
}

void atclient_atnotification_encKeyName_set_initialized(atclient_atnotification *notification, bool initialized)
{
  if (initialized) {
    notification->initalizedfields[1] |= ATCLIENT_ATNOTIFICATION_ENCKEYNAME_INITIALIZED;
  } else {
    notification->initalizedfields[1] &= ~ATCLIENT_ATNOTIFICATION_ENCKEYNAME_INITIALIZED;
  }
}

void atclient_atnotification_encAlgo_set_initialized(atclient_atnotification *notification, bool initialized)
{
  if (initialized) {
    notification->initalizedfields[1] |= ATCLIENT_ATNOTIFICATION_ENCALGO_INITIALIZED;
  } else {
    notification->initalizedfields[1] &= ~ATCLIENT_ATNOTIFICATION_ENCALGO_INITIALIZED;
  }
}

void atclient_atnotification_ivNonce_set_initialized(atclient_atnotification *notification, bool initialized)
{
  if (initialized) {
    notification->initalizedfields[1] |= ATCLIENT_ATNOTIFICATION_IVNONCE_INITIALIZED;
  } else {
    notification->initalizedfields[1] &= ~ATCLIENT_ATNOTIFICATION_IVNONCE_INITIALIZED;
  }
}

void atclient_atnotification_skeEncKeyName_set_initialized(atclient_atnotification *notification, bool initialized)
{
  if (initialized) {
    notification->initalizedfields[1] |= ATCLIENT_ATNOTIFICATION_SKEENCKEYNAME_INITIALIZED;
  } else {
    notification->initalizedfields[1] &= ~ATCLIENT_ATNOTIFICATION_SKEENCKEYNAME_INITIALIZED;
  }
}

void atclient_atnotification_skeEncAlgo_set_initialized(atclient_atnotification *notification, bool initialized)
{
  if (initialized) {
    notification->initalizedfields[1] |= ATCLIENT_ATNOTIFICATION_SKEENCALGO_INITIALIZED;
  } else {
    notification->initalizedfields[1] &= ~ATCLIENT_ATNOTIFICATION_SKEENCALGO_INITIALIZED;
  }
}


void atclient_atnotification_free_id(atclient_atnotification *notification) {
  free(notification->id);
  notification->id = NULL;
  atclient_atnotification_id_set_initialized(notification, false);
}

void atclient_atnotification_free_from(atclient_atnotification *notification) {
  free(notification->from);
  notification->from = NULL;
  atclient_atnotification_from_set_initialized(notification, false);
}

void atclient_atnotification_free_to(atclient_atnotification *notification) {
  free(notification->to);
  notification->to = NULL;
  atclient_atnotification_to_set_initialized(notification, false);
}
void atclient_atnotification_free_key(atclient_atnotification *notification) {
  free(notification->key);
  notification->key = NULL;
  atclient_atnotification_key_set_initialized(notification, false);
}
void atclient_atnotification_free_value(atclient_atnotification *notification) {
  if (atclient_atnotification_value_is_initialized(notification)) {
    free(notification->value);
    notification->value = NULL;
  }
  atclient_atnotification_value_set_initialized(notification, false);
}
void atclient_atnotification_free_operation(atclient_atnotification *notification) {
  free(notification->operation);
  notification->operation = NULL;
  atclient_atnotification_operation_set_initialized(notification, false);
}
void atclient_atnotification_free_epochMillis(atclient_atnotification *notification) {
  notification->epochMillis = 0;
  atclient_atnotification_epochMillis_set_initialized(notification, false);
}

void atclient_atnotification_free_messageType(atclient_atnotification *notification) {
  free(notification->messageType);
  notification->messageType = NULL;
  atclient_atnotification_messageType_set_initialized(notification, false);
}

void atclient_atnotification_free_isEncrypted(atclient_atnotification *notification) {
  notification->isEncrypted = false;
  atclient_atnotification_isEncrypted_set_initialized(notification, false);
}

void atclient_atnotification_free_encKeyName(atclient_atnotification *notification)
{
  free(notification->encKeyName);
  notification->encKeyName = NULL;
  atclient_atnotification_encKeyName_set_initialized(notification, false);
}

void atclient_atnotification_free_encAlgo(atclient_atnotification *notification)
{
  free(notification->encAlgo);
  notification->encAlgo = NULL;
  atclient_atnotification_encAlgo_set_initialized(notification, false);
}

void atclient_atnotification_free_ivNonce(atclient_atnotification *notification)
{
  free(notification->ivNonce);
  notification->ivNonce = NULL;
  atclient_atnotification_ivNonce_set_initialized(notification, false);
}

void atclient_atnotification_free_skeEncKeyName(atclient_atnotification *notification)
{
  free(notification->skeEncKeyName);
  notification->skeEncKeyName = NULL;
  atclient_atnotification_skeEncKeyName_set_initialized(notification, false);
}

void atclient_atnotification_free_skeEncAlgo(atclient_atnotification *notification)
{
  free(notification->skeEncAlgo);
  notification->skeEncAlgo = NULL;
  atclient_atnotification_skeEncAlgo_set_initialized(notification, false);
}


void atclient_atnotification_set_id(atclient_atnotification *notification, const char *id, const size_t idlen) {
  if (atclient_atnotification_id_is_initialized(notification)) {
    atclient_atnotification_free_id(notification);
  }
  notification->id = malloc(sizeof(char) * (idlen + 1));
  memcpy(notification->id, id, idlen);
  *(notification->id + idlen) = '\0';
  atclient_atnotification_id_set_initialized(notification, true);
}

void atclient_atnotification_set_from(atclient_atnotification *notification, const char *from, const size_t fromlen) {
  if (atclient_atnotification_from_is_initialized(notification)) {
    atclient_atnotification_free_from(notification);
  }
  notification->from = malloc(sizeof(char) * (fromlen + 1));
  memcpy(notification->from, from, fromlen);
  *(notification->from + fromlen) = '\0';
  atclient_atnotification_from_set_initialized(notification, true);
}

void atclient_atnotification_set_to(atclient_atnotification *notification, const char *to, const size_t tolen) {
  if (atclient_atnotification_to_is_initialized(notification)) {
    atclient_atnotification_free_to(notification);
  }
  notification->to = malloc(sizeof(char) * (tolen + 1));
  memcpy(notification->to, to, tolen);
  *(notification->to + tolen) = '\0';
  atclient_atnotification_to_set_initialized(notification, true);
}

void atclient_atnotification_set_key(atclient_atnotification *notification, const char *key, const size_t keylen) {
  if (atclient_atnotification_key_is_initialized(notification)) {
    atclient_atnotification_free_key(notification);
  }
  notification->key = malloc(sizeof(char) * (keylen + 1));
  memcpy(notification->key, key, keylen);
  *(notification->key + keylen) = '\0';
  atclient_atnotification_key_set_initialized(notification, true);
}

void atclient_atnotification_set_value(atclient_atnotification *notification, const char *value,
                                       const size_t valuelen) {
  if (atclient_atnotification_value_is_initialized(notification)) {
    atclient_atnotification_free_value(notification);
  }
  notification->value = malloc(sizeof(char) * (valuelen + 1));
  memcpy(notification->value, value, valuelen);
  *(notification->value + valuelen) = '\0';
  atclient_atnotification_value_set_initialized(notification, true);
}

void atclient_atnotification_set_operation(atclient_atnotification *notification, const char *operation,
                                           const size_t operationlen) {
  if (atclient_atnotification_operation_is_initialized(notification)) {
    atclient_atnotification_free_operation(notification);
  }
  notification->operation = malloc(sizeof(char) * (operationlen + 1));
  memcpy(notification->operation, operation, operationlen);
  *(notification->operation + operationlen) = '\0';
  atclient_atnotification_operation_set_initialized(notification, true);
}

void atclient_atnotification_set_epochMillis(atclient_atnotification *notification, const size_t epochMillis) {
  if (atclient_atnotification_epochMillis_is_initialized(notification)) {
    atclient_atnotification_free_epochMillis(notification);
  }
  notification->epochMillis = epochMillis;
  atclient_atnotification_epochMillis_set_initialized(notification, true);
}

void atclient_atnotification_set_messageType(atclient_atnotification *notification, const char *messageType,
                                             const size_t messageTypelen) {
  if (atclient_atnotification_messageType_is_initialized(notification)) {
    atclient_atnotification_free_messageType(notification);
  }
  notification->messageType = malloc(sizeof(char) * (messageTypelen + 1));
  memcpy(notification->messageType, messageType, messageTypelen);
  *(notification->messageType + messageTypelen) = '\0';
  atclient_atnotification_messageType_set_initialized(notification, true);
}

void atclient_atnotification_set_isEncrypted(atclient_atnotification *notification, const bool isEncrypted) {
  if (atclient_atnotification_isEncrypted_is_initialized(notification)) {
    atclient_atnotification_free_isEncrypted(notification);
  }
  notification->isEncrypted = isEncrypted;
  atclient_atnotification_isEncrypted_set_initialized(notification, true);
}

void atclient_atnotification_set_encKeyName(atclient_atnotification *notification, const char *encKeyName,
                                            const size_t encKeyNamelen) {
  if (atclient_atnotification_encKeyName_is_initialized(notification)) {
    atclient_atnotification_free_encKeyName(notification);
  }
  notification->encKeyName = malloc(sizeof(char) * (encKeyNamelen + 1));
  memcpy(notification->encKeyName, encKeyName, encKeyNamelen);
  *(notification->encKeyName + encKeyNamelen) = '\0';
  atclient_atnotification_encKeyName_set_initialized(notification, true);
}

void atclient_atnotification_set_encAlgo(atclient_atnotification *notification, const char *encAlgo,
                                         const size_t encAlgolen) {
  if (atclient_atnotification_encAlgo_is_initialized(notification)) {
    atclient_atnotification_free_encAlgo(notification);
  }
  notification->encAlgo = malloc(sizeof(char) * (encAlgolen + 1));
  memcpy(notification->encAlgo, encAlgo, encAlgolen);
  *(notification->encAlgo + encAlgolen) = '\0';
  atclient_atnotification_encAlgo_set_initialized(notification, true);
}

void atclient_atnotification_set_ivNonce(atclient_atnotification *notification, const char *ivNonce,
                                         const size_t ivNoncelen) {
  if (atclient_atnotification_ivNonce_is_initialized(notification)) {
    atclient_atnotification_free_ivNonce(notification);
  }
  notification->ivNonce = malloc(sizeof(char) * (ivNoncelen + 1));
  memcpy(notification->ivNonce, ivNonce, ivNoncelen);
  *(notification->ivNonce + ivNoncelen) = '\0';
  atclient_atnotification_ivNonce_set_initialized(notification, true);
}

void atclient_atnotification_set_skeEncKeyName(atclient_atnotification *notification, const char *skeEncKeyName,
                                               const size_t skeEncKeyNamelen) {
  if (atclient_atnotification_skeEncKeyName_is_initialized(notification)) {
    atclient_atnotification_free_skeEncKeyName(notification);
  }
  notification->skeEncKeyName = malloc(sizeof(char) * (skeEncKeyNamelen + 1));
  memcpy(notification->skeEncKeyName, skeEncKeyName, skeEncKeyNamelen);
  *(notification->skeEncKeyName + skeEncKeyNamelen) = '\0';
  atclient_atnotification_skeEncKeyName_set_initialized(notification, true);
}

void atclient_atnotification_set_skeEncAlgo(atclient_atnotification *notification, const char *skeEncAlgo,
                                            const size_t skeEncAlgolen) {
  if (atclient_atnotification_skeEncAlgo_is_initialized(notification)) {
    atclient_atnotification_free_skeEncAlgo(notification);
  }
  notification->skeEncAlgo = malloc(sizeof(char) * (skeEncAlgolen + 1));
  memcpy(notification->skeEncAlgo, skeEncAlgo, skeEncAlgolen);
  *(notification->skeEncAlgo + skeEncAlgolen) = '\0';
  atclient_atnotification_skeEncAlgo_set_initialized(notification, true);
}


void atclient_monitor_message_init(atclient_monitor_message *message) {
  memset(message, 0, sizeof(atclient_monitor_message));
}

void atclient_monitor_message_free(atclient_monitor_message *message) {
  if (message->type == ATCLIENT_MONITOR_MESSAGE_TYPE_NOTIFICATION) {
    atclient_atnotification_free(&(message->notification));
  } else if (message->type == ATCLIENT_MONITOR_MESSAGE_TYPE_DATA_RESPONSE) {
    free(message->data_response);
  } else if (message->type == ATCLIENT_MONITOR_MESSAGE_TYPE_ERROR_RESPONSE) {
    free(message->error_response);
  }
}

void atclient_monitor_init(atclient *monitor_conn) { memset(monitor_conn, 0, sizeof(atclient)); }
void atclient_monitor_free(atclient *monitor_conn) { return; }

int atclient_start_monitor(atclient *monitor_conn, atclient_connection *root_conn, const char *atsign,
                           const atclient_atkeys *atkeys, const char *regex, const size_t regexlen) {
  int ret = 1;

  size_t cmdsize = 0;
  char *cmd = NULL;

  // 1. initialize monitor_conn
  ret = atclient_pkam_authenticate(monitor_conn, root_conn, atkeys, atsign);
  if (ret != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "Failed to authenticate with PKAM\n");
    goto exit;
  }

  // log building command... (Debug)
  atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_DEBUG, "Building monitor command...\n");

  // 2. build cmd
  cmdsize += 7 + 2; // monitor + \r\n
  if (regexlen > 0) {
    cmdsize += regexlen + 1; // $regex + ' '
  }
  cmdsize += 1; // null terminator
  cmd = malloc(sizeof(char) * cmdsize);
  memset(cmd, 0, sizeof(char) * cmdsize);

  if (regexlen > 0) {
    snprintf(cmd, cmdsize, "monitor %.*s\r\n", (int)regexlen, regex);
  } else {
    snprintf(cmd, cmdsize, "monitor\r\n");
  }

  // 3. send monitor cmd
  ret = mbedtls_ssl_write(&(monitor_conn->secondary_connection.ssl), (unsigned char *)cmd, cmdsize - 1);
  if (ret < 0 || ret != cmdsize - 1) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "Failed to send monitor command: %d\n", ret);
    goto exit;
  }

  atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_INFO, "Sent monitor command: \'%s\'\n", cmd);

  ret = 0;
  goto exit;
exit: {
  free(cmd);
  return ret;
}
}

int atclient_send_heartbeat(atclient *monitor_conn) {
  int ret = -1;
  const char *command = "noop:0\r\n";

  ret = mbedtls_ssl_write(&(monitor_conn->secondary_connection.ssl), (const unsigned char *)command, strlen(command));
  if (ret < 0 || ret != 8) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "Failed to send monitor command: %d\n", ret);
    goto exit;
  }
  // atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_DEBUG, "Sent heartbeat (%d bytes sent)\n", ret);
  ret = 0;
  goto exit;

exit: { return ret; }
}

int atclient_monitor_read(atclient *monitor_conn, atclient_monitor_message **message) {
  int ret = -1;

  const size_t chunksize = ATCLIENT_MONITOR_BUFFER_LEN;

  size_t chunks = 0;
  char *buffer = malloc(sizeof(char) * chunksize);
  memset(buffer, 0, sizeof(char) * chunksize);
  char *buffertemp = NULL;

  bool done_reading = false;
  while (!done_reading) {
    // atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_DEBUG, "Reading chunk...\n");
    if (chunks > 0) {
      buffertemp = realloc(buffer, sizeof(char) * (chunksize + (chunksize * chunks)));
      buffer = buffertemp;
      buffertemp = NULL;
    }

    size_t off = chunksize * chunks;
    for (int i = 0; i < chunksize; i++) {
      ret = mbedtls_ssl_read(&(monitor_conn->secondary_connection.ssl), (unsigned char *)buffer + off + i, 1);
      if (ret < 0 || buffer[off + i] == '\n') {
        buffer[off + i] = '\0';
        done_reading = true;
        break;
      }
    }
    chunks = chunks + 1;
  }
  if (ret < 0) {
    goto exit;
  }

  int i = 0;
  while (buffer[i] != ':') {
    i++;
  }

  // print buffer
  // atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_DEBUG, "Buffer: %s\n", buffer);

  char *messagetype = NULL;
  char *messagebody = NULL;
  ret = parse_message(buffer, &messagetype, &messagebody);
  if (ret != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "Failed to find message type and message body from: %s\n", buffer);
    goto exit;
  }

  atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_DEBUG, "Message Type: %s\n", messagetype);
  atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_DEBUG, "Message Body: %s\n", messagebody);

  *message = malloc(sizeof(atclient_monitor_message));
  atclient_monitor_message_init(*message);

  if (strcmp(messagetype, "notification") == 0) {
    (*message)->type = ATCLIENT_MONITOR_MESSAGE_TYPE_NOTIFICATION;
    atclient_atnotification_init(&((*message)->notification));
    if ((ret = parse_notification(&((*message)->notification), messagebody)) != 0) {
      atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "Failed to parse notification\n");
      goto exit;
    }
  } else if (strcmp(messagetype, "data") == 0) {
    (*message)->type = ATCLIENT_MONITOR_MESSAGE_TYPE_DATA_RESPONSE;
    (*message)->data_response = malloc(strlen(messagebody) + 1);
    strcpy((*message)->data_response, messagebody);
  } else if (strcmp(messagetype, "error") == 0) {
    (*message)->type = ATCLIENT_MONITOR_MESSAGE_TYPE_ERROR_RESPONSE;
    (*message)->error_response = malloc(strlen(messagebody) + 1);
    strcpy((*message)->error_response, messagebody);
  } else {
    (*message)->type = ATCLIENT_MONITOR_MESSAGE_TYPE_NONE;
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "Failed to identify message type from \"%s\"\n", buffer);
    ret = -1;
    goto exit;
  }

  ret = 0;
  goto exit;
exit: {
  free(buffer);
  free(buffertemp);
  return ret;
}
}

static int parse_message(char *original, char **message_type, char **message_body) {
  int ret = -1;

  char *temp = NULL;
  char *saveptr;

  temp = strtok_r(original, ":", &saveptr);
  if (temp == NULL) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "Failed to parse message type\n");
    goto exit;
  }
  *message_type = temp;

  temp = strtok_r(NULL, "\n", &saveptr);
  if (temp == NULL) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "Failed to parse message body\n");
    goto exit;
  }
  *message_body = temp;

  // if message_type starts with `@`, then it will follow this format: `@<atsign>@<message_type>`
  // extract message_type from message_type
  if ((*message_type)[0] == '@') {
    char *temp = strtok_r(*message_type, "@", &saveptr);
    if (temp == NULL) {
      atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "Failed to parse message type\n");
      goto exit;
    }
    *message_type = strtok_r(NULL, "@", &saveptr);
    if (*message_type == NULL) {
      atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "Failed to parse message type\n");
      goto exit;
    }
  }

  // if message_body has any leading or trailing white space or new line characters, remove it
  while ((*message_body)[0] == ' ' || (*message_body)[0] == '\n') {
    *message_body = *message_body + 1;
  }
  size_t trail;
  do {
    trail = strlen(*message_body) - 1;
    if ((*message_body)[trail] == ' ' || (*message_body)[trail] == '\n') {
      (*message_body)[trail] = '\0';
    }
  } while ((*message_body)[trail] == ' ' || (*message_body)[trail] == '\n');

  ret = 0;
  goto exit;
exit: { return ret; }
}

static int parse_notification(atclient_atnotification *notification, const char *messagebody) {
  int ret = -1;

  // log "parsing notification..."
  atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_DEBUG, "Parsing notification...\n");

  cJSON *root = NULL;

  root = cJSON_Parse(messagebody);
  if (root == NULL) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "Failed to parse notification body using cJSON: \"%s\"\n",
                 messagebody);
    ret = -1;
    goto exit;
  }

  char *val;
  size_t vallen;

  cJSON *id = cJSON_GetObjectItem(root, "id");
  if (id != NULL) {
    if (id->type != cJSON_NULL) {
      val = id->valuestring;
      vallen = strlen(id->valuestring);
    } else {
      val = "null";
      vallen = strlen("null");
    }
    atclient_atnotification_set_id(notification, val, vallen);
  }

  cJSON *from = cJSON_GetObjectItem(root, "from");
  if (from != NULL) {
    if (from->type != cJSON_NULL) {
      val = from->valuestring;
      vallen = strlen(from->valuestring);
    } else {
      val = "null";
      vallen = strlen("null");
    }
    atclient_atnotification_set_from(notification, val, vallen);
  }

  cJSON *to = cJSON_GetObjectItem(root, "to");
  if (to != NULL) {
    if (to->type != cJSON_NULL) {
      val = to->valuestring;
      vallen = strlen(to->valuestring);
    } else {
      val = "null";
      vallen = strlen("null");
    }
    atclient_atnotification_set_to(notification, val, vallen);
  }

  cJSON *key = cJSON_GetObjectItem(root, "key");
  if (key != NULL) {
    if (key->type != cJSON_NULL) {
      val = key->valuestring;
      vallen = strlen(key->valuestring);
    } else {
      val = "null";
      vallen = strlen("null");
    }
    atclient_atnotification_set_key(notification, val, vallen);
  }

  cJSON *value = cJSON_GetObjectItem(root, "value");
  if (value != NULL) {
    if (value->type != cJSON_NULL) {
      val = value->valuestring;
      vallen = strlen(value->valuestring);
    } else {
      val = "null";
      vallen = strlen("null");
    }
    atclient_atnotification_set_value(notification, val, vallen);
  }

  cJSON *operation = cJSON_GetObjectItem(root, "operation");
  if (operation != NULL) {
    if (operation->type != cJSON_NULL) {
      val = operation->valuestring;
      vallen = strlen(operation->valuestring);
    } else {
      val = "null";
      vallen = strlen("null");
    }
    atclient_atnotification_set_operation(notification, val, vallen);
  }

  cJSON *epochMillis = cJSON_GetObjectItem(root, "epochMillis");
  if (epochMillis != NULL) {
    atclient_atnotification_set_epochMillis(notification, epochMillis->valueint);
  }

  cJSON *messageType = cJSON_GetObjectItem(root, "messageType");
  if (messageType != NULL) {
    if (messageType->type != cJSON_NULL) {
      val = messageType->valuestring;
      vallen = strlen(messageType->valuestring);
    } else {
      val = "null";
      vallen = strlen("null");
    }
    atclient_atnotification_set_messageType(notification, val, vallen);
  }

  cJSON *isEncrypted = cJSON_GetObjectItem(root, "isEncrypted");
  if (isEncrypted != NULL) {
    atclient_atnotification_set_isEncrypted(notification, isEncrypted->valueint);
  }

  cJSON *metadata = cJSON_GetObjectItem(root, "metadata");
  if (metadata != NULL) {
    // get encKeyName
    cJSON *encKeyName = cJSON_GetObjectItem(metadata, "encKeyName");
    if (encKeyName != NULL) {
      if (encKeyName->type != cJSON_NULL) {
        val = encKeyName->valuestring;
        vallen = strlen(encKeyName->valuestring);
      } else {
        val = "null";
        vallen = strlen("null");
      }
      atclient_atnotification_set_encKeyName(notification, val, vallen);
    }

    // get encAlgo
    cJSON *encAlgo = cJSON_GetObjectItem(metadata, "encAlgo");
    if (encAlgo != NULL) {
      if (encAlgo->type != cJSON_NULL) {
        val = encAlgo->valuestring;
        vallen = strlen(encAlgo->valuestring);
      } else {
        val = "null";
        vallen = strlen("null");
      }
      atclient_atnotification_set_encAlgo(notification, val, vallen);
    }

    // get ivNonce
    cJSON *ivNonce = cJSON_GetObjectItem(metadata, "ivNonce");
    if(ivNonce != NULL) {
      if (ivNonce->type != cJSON_NULL) {
        val = ivNonce->valuestring;
        vallen = strlen(ivNonce->valuestring);
      } else {
        val = "null";
        vallen = strlen("null");
      }
      atclient_atnotification_set_ivNonce(notification, val, vallen);
    }

    // get skeEncKeyName
    cJSON *skeEncKeyName = cJSON_GetObjectItem(metadata, "skeEncKeyName");
    if (skeEncKeyName != NULL) {
      if (skeEncKeyName->type != cJSON_NULL) {
        val = skeEncKeyName->valuestring;
        vallen = strlen(skeEncKeyName->valuestring);
      } else {
        val = "null";
        vallen = strlen("null");
      }
      atclient_atnotification_set_skeEncKeyName(notification, val, vallen);
    }

    // get skeEncAlgo
    cJSON *skeEncAlgo = cJSON_GetObjectItem(metadata, "skeEncAlgo");
    if (skeEncAlgo != NULL) {
      if (skeEncAlgo->type != cJSON_NULL) {
        val = skeEncAlgo->valuestring;
        vallen = strlen(skeEncAlgo->valuestring);
      } else {
        val = "null";
        vallen = strlen("null");
      }
      atclient_atnotification_set_skeEncAlgo(notification, val, vallen);
    }
  }

  ret = 0;
  goto exit;

exit: {
  cJSON_Delete(root);
  return ret;
}
}
