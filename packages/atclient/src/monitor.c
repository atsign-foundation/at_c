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

void atclient_monitor_free(atclient *monitor_ctx) { return; }

void atclient_monitor_init(atclient *monitor_ctx) {
  memset(monitor_ctx, 0, sizeof(atclient));
  // atclient_init(monitor_ctx);
  // // TODO: these structs are copied over, but the underlying memory addresses are the same
  // // we should migrate atsign in the atclient struct to be char, since .withoutat is simply just (atsign + 1)
  // // atkeys we need to copy each bit of memory one by one
  // monitor_ctx->atsign = atsign;
  // monitor_ctx->atkeys = atkeys;
}

void atclient_monitor_message_free(atclient_monitor_message *message) {
  // free(message->notification.id);
  // atclient_atkey_free(&message->notification.key);
  // atclient_atsign_free(&message->notification.from);
  // atclient_atsign_free(&message->notification.to);
  // free(message->notification.value);
  return;
}

static int auth(atclient *monitor, const char *root_host,const  int root_port, const char *atsign,
                const atclient_atkeys atkeys) {
  int ret = 1;

  atclient_connection root_conn;
  atclient_connection_init(&root_conn);

  ret = atclient_connection_connect(&root_conn, root_host, root_port);
  if (ret != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "Failed to connect to root server: %d\n", ret);
    goto exit;
  }

  ret = atclient_pkam_authenticate(monitor, &root_conn, &atkeys, atsign);
  if (ret != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "Failed to authenticate: %d\n", ret);
    goto exit;
  }

  ret = atclient_atsign_init(&(monitor->atsign), atsign);
  if (ret != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "Failed to initialize atsign: %d\n", ret);
    goto exit;
  }

  monitor->atkeys = atkeys; // TODO: optimize later, we should not copy the entire struct

  goto exit;
exit: {
  atclient_connection_free(&root_conn);
  return ret;
}
}

int atclient_monitor_start_connection(atclient *monitor, const char *root_host, const int root_port, const char *atsign,
                                      const atclient_atkeys *atkeys, const char *regex) {
  int ret = 1;

  size_t cmd_len = 7 + 2; // "monitor" + '\r\n'
  size_t regex_len = strlen(regex);

  if (regex_len > 0) {
    cmd_len += regex_len + 1;
  }

  cmd_len += 1; // for '\0'

  char cmd[cmd_len];
  if (regex_len > 0) {
    sprintf(cmd, "monitor %s\r\n", regex);
  } else {
    sprintf(cmd, "monitor\r\n");
  }

  if ((ret = auth(monitor, root_host, root_port, atsign, *atkeys)) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "Failed to authenticate: %d\n", ret);
    goto exit;
  }

  ret = mbedtls_ssl_write(&(monitor->secondary_connection.ssl), (unsigned char *)cmd, cmd_len);
  if (ret < 0 || ret != cmd_len) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "Failed to send monitor command. mbedtls_ssl_write: %d\n", ret);
    goto exit;
  }
  atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_DEBUG, "Sent monitor command: \"%s\"\n", cmd);

  ret = 0;
  goto exit;
exit: { return ret; }
}

int atclient_monitor_send_heartbeat(atclient *ctx) {
  int ret = -1;
  unsigned char command[9] = "noop:0\r\n\0";

  ret = mbedtls_ssl_write(&(ctx->secondary_connection.ssl), command, 9);
  if (ret < 0 || ret != 9) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "Failed to send monitor command");
  } else {
    ret = 0;
  }

  return ret;
}

static int parse_notification(atclient_monitor_message *message, char *message_body);

int atclient_monitor_read(atclient *monitor_connection, atclient_monitor_message *message) {
  int ret = -1;

  size_t chunk_size = ATCLIENT_MONITOR_BUFFER_LEN;
  int chunks = 0;
  char *buffer = calloc(chunk_size, sizeof(char));
  char *tmp_buffer = NULL;

  bool done_reading = 0;

  while (done_reading == 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_DEBUG, "Reading chunk\n");
    if (chunks > 0) {
      tmp_buffer = realloc(buffer, chunk_size + (chunk_size * chunks) * sizeof(char));
      buffer = tmp_buffer;
      tmp_buffer = NULL;
    }

    size_t off = chunk_size * chunks;
    for (int i = 0; i < chunk_size; i++) {
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
    message->type = ATCLIENT_MONITOR_MESSAGE_TYPE_DATA;
    message->data_response = message_body;
  } else if (strcmp(message_type, "notification") == 0) {
    message->type = ATCLIENT_MONITOR_MESSAGE_TYPE_NOTIFICATION;
    ret = parse_notification(message, message_body);
    if (ret != 0) {
      atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "Failed to parse notification: %d\n", ret);
    }
  } else if (strcmp(message_type, "error") == 0) {
    message->type = ATCLIENT_MONITOR_MESSAGE_TYPE_ERROR;
    message->error_response = message_body;
  } else {
    message->type = ATCLIENT_MONITOR_MESSAGE_TYPE_NONE;
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "Failed to identify message type");
    ret = -1;
  }

  free(buffer);
  return ret;
}

static int parse_notification(atclient_monitor_message *message, char *message_body) {
  int ret = -1;

  cJSON *root = NULL;
  root = cJSON_Parse(message_body);
  if (root == NULL) {
    cJSON_Delete(root);
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "Failed to parse notification body");
    ret = -1;
    return ret;
  }

  cJSON *key = cJSON_GetObjectItem(root, "key");
  atclient_atkey_init(&(message->notification.key));
  atclient_atkey_from_string(&(message->notification.key), key->valuestring, strlen(key->valuestring));

  cJSON *id = cJSON_GetObjectItem(root, "id");
  // message->notification.id = malloc((strlen(id->valuestring) + 1) * sizeof(char));
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
