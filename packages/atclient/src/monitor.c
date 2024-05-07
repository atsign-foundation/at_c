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

void atclient_monitor_message_init(atclient_monitor_message *message) {
  memset(message, 0, sizeof(atclient_monitor_message));
}

void atclient_monitor_message_free(atclient_monitor_message *message) {
  memset(message, 0, sizeof(atclient_monitor_message));
  // free(message->notification.id);
  // atclient_atkey_free(&message->notification.key);
  // atclient_atsign_free(&message->notification.from);
  // atclient_atsign_free(&message->notification.to);
  // free(message->notification.value);
}

void atclient_monitor_init(atclient *monitor_conn) {
  memset(monitor_conn, 0, sizeof(atclient));
  // atclient_init(monitor_ctx);
  // // TODO: these structs are copied over, but the underlying memory addresses are the same
  // // we should migrate atsign in the atclient struct to be char, since .withoutat is simply just (atsign + 1)
  // // atkeys we need to copy each bit of memory one by one
  // monitor_ctx->atsign = atsign;
  // monitor_ctx->atkeys = atkeys;
}

void atclient_monitor_free(atclient *monitor_conn) { memset(monitor_conn, 0, sizeof(atclient)); }

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

  ret = mbedtls_ssl_write(&(monitor_conn->secondary_connection.ssl), (const unsigned char *) command, strlen(command));
  if (ret < 0 || ret != 8) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "Failed to send monitor command: %d\n", ret);
    goto exit;
  }
  // atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_DEBUG, "Sent heartbeat (%d bytes sent)\n", ret);
  ret = 0;
  goto exit;

exit: { return ret; }
}

static int parse_notification(atclient_monitor_message *message, char *message_body);

int atclient_read_monitor(atclient *monitor_connection, atclient_monitor_message *message) {
  int ret = -1;

  size_t chunksize = ATCLIENT_MONITOR_BUFFER_LEN;
  int chunks = 0;
  char *buffer = malloc(sizeof(char) * chunksize);
  char *tmp_buffer = NULL;

  bool done_reading = false;
  while (!done_reading) {
    atlogger_log("parse_notification", ATLOGGER_LOGGING_LEVEL_DEBUG, "Reading chunk...\n");
    if (chunks > 0) {
      tmp_buffer = realloc(buffer, chunksize + (chunksize * chunks) * sizeof(char));
      buffer = tmp_buffer;
      tmp_buffer = NULL;
    }

    size_t off = chunksize * chunks;
    for (int i = 0; i < chunksize; i++) {
      ret = mbedtls_ssl_read(&(monitor_connection->secondary_connection.ssl), (unsigned char *)buffer + off + i, 1);
      if (ret < 0 || buffer[off + i] == '\n') {
        buffer[off + i] = '\0';
        done_reading = 1;
        break;
      }
    }
    chunks = chunks + 1;
  }
  if (ret < 0) {
    free(buffer);
    return ret;
  }

  int i = 0;
  while (buffer[i] != ':') {
    i++;
  }

  const char *message_type = strtok(buffer, ":"); // everything up to first ':'
  char *message_body = strtok(NULL, "\n");
  message_body = message_body + 1;

  if (strcmp(message_type, "data") == 0) {
    message->type = ATCLIENT_MONITOR_MESSAGE_TYPE_DATA_RESPONSE;
    message->data_response = message_body;
  } else if (strcmp(message_type, "notification") == 0) {
    message->type = ATCLIENT_MONITOR_MESSAGE_TYPE_NOTIFICATION;
    ret = parse_notification(message, message_body);
    if (ret != 0) {
      atlogger_log("atclient_read_monitor", ATLOGGER_LOGGING_LEVEL_ERROR, "Failed to parse notification: %d\n", ret);
    }
  } else if (strcmp(message_type, "error") == 0) {
    message->type = ATCLIENT_MONITOR_MESSAGE_TYPE_ERROR_RESPONSE;
    message->error_response = message_body;
  } else {
    message->type = ATCLIENT_MONITOR_MESSAGE_TYPE_NONE;
    atlogger_log("atclient_read_monitor", ATLOGGER_LOGGING_LEVEL_ERROR, "Failed to identify message type\n");
    ret = -1;
    goto exit;
  }

  ret = 0;
  goto exit;

exit: {
  free(buffer);
  return ret;
}
}

static int parse_notification(atclient_monitor_message *message, char *message_body) {
  int ret = -1;

  cJSON *root = NULL;
  root = cJSON_Parse(message_body);
  if (root == NULL) {
    cJSON_Delete(root);
    atlogger_log("parse_notification", ATLOGGER_LOGGING_LEVEL_ERROR, "Failed to parse notification body\n");
    ret = -1;
    return ret;
  }

  cJSON *key = cJSON_GetObjectItem(root, "key");
  atclient_atkey_init(&(message->notification.key));
  atclient_atkey_from_string(&(message->notification.key), key->valuestring, strlen(key->valuestring));

  if (false) { // TODO: if regex doesnt match // do we even need this now?
    atlogger_log("parse_notification", ATLOGGER_LOGGING_LEVEL_ERROR, "Regex failed to match\n");
    cJSON_Delete(root);
    atclient_monitor_message_free(message);
    ret = -1;
    return ret;
  }

  cJSON *id = cJSON_GetObjectItem(root, "id");
  message->notification.id = malloc((strlen(id->valuestring) + 1) * sizeof(char));
  strcpy(message->notification.id, id->valuestring);

  cJSON *metadata = cJSON_GetObjectItem(root, "metadata");
  if (metadata != NULL) {
    atclient_atkey_metadata_from_cjson_node(&(message->notification.key.metadata), metadata);
  }

  cJSON *from = cJSON_GetObjectItem(root, "from");
  atclient_atsign_init(&message->notification.from, from->valuestring);

  cJSON *to = cJSON_GetObjectItem(root, "to");
  atclient_atsign_init(&message->notification.to, to->valuestring);

  cJSON *epochMillis = cJSON_GetObjectItem(root, "epochMillis");
  if (epochMillis != NULL) {
    if (epochMillis->type != cJSON_NULL) {
      message->notification.epochMillis = epochMillis->valueint;
    } else {
      message->notification.epochMillis = 0;
    }
  }

  cJSON *messageType = cJSON_GetObjectItem(root, "messageType");
  if (messageType != NULL) {
    if (messageType->type != cJSON_NULL) {
      strcpy(message->notification.messageType, messageType->valuestring);
    } else {
      strcpy(message->notification.messageType, "null");
    }
  }

  cJSON *isEncrypted = cJSON_GetObjectItem(root, "isEncrypted");
  if (isEncrypted != NULL) {
    if (isEncrypted->type != cJSON_NULL) {
      message->notification.isEncrypted = isEncrypted->valueint != 0;
    } else {
      message->notification.isEncrypted = false;
    }
  }

  cJSON *value = cJSON_GetObjectItem(root, "value");
  if (value != NULL) {
    if (value->type != cJSON_NULL) {
      message->notification.value = malloc(strlen(value->valuestring) + 1);
      strcpy(message->notification.value, value->valuestring);
    } else {
      message->notification.value = malloc(strlen("null") + 1);
      strcpy(message->notification.value, "null");
    }
  }

  cJSON *operation = cJSON_GetObjectItem(root, "operation");
  if (operation != NULL) {
    if (operation->type != cJSON_NULL) {
      strcpy(message->notification.operation, operation->valuestring);
    } else {
      strcpy(message->notification.operation, "null");
    }
  }

  cJSON *expiresAt = cJSON_GetObjectItem(root, "expiresAt");
  if (expiresAt != NULL) {
    if (expiresAt->type != cJSON_NULL) {
      message->notification.expiresAt = expiresAt->valueint;
    } else {
      message->notification.expiresAt = 0;
    }
  }

  cJSON_Delete(root);
  ret = 0;
  return ret;
}
