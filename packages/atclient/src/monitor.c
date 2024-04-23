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

void atclient_monitor_message_free(atclient_monitor_message *message) {
  free(message->notification.id);
  atclient_atkey_free(&message->notification.key);
  atclient_atsign_free(&message->notification.from);
  atclient_atsign_free(&message->notification.to);
  free(message->notification.value);
}

void atclient_monitor_init(atclient *monitor_ctx, const atclient_atsign atsign, const atclient_atkeys atkeys) {
  atclient_init(monitor_ctx);
  // TODO: these structs are copied over, but the underlying memory addresses are the same
  // we should migrate atsign in the atclient struct to be char, since .withoutat is simply just (atsign + 1)
  // atkeys we need to copy each bit of memory one by one
  monitor_ctx->atsign = atsign;
  monitor_ctx->atkeys = atkeys;
}

int atclient_start_monitor(atclient *monitor_ctx, const char *root_host, const int root_port, const char *regex) {
  int res = 1;

  atclient_connection root_connection;
  atclient_connection_init(&root_connection);
  atclient_connection_connect(&root_connection, root_host, root_port);

  res = atclient_pkam_authenticate(monitor_ctx, &root_connection, monitor_ctx->atkeys, monitor_ctx->atsign.atsign,
                                   strlen(monitor_ctx->atsign.atsign));
  atclient_connection_free(&root_connection);

  if (res != 0) {
    atclient_atlogger_log("atclient_start_monitor", ATLOGGER_LOGGING_LEVEL_ERROR, "Failed to pkam authenticate");
    atclient_free(monitor_ctx);
    return res;
  }

  size_t cmd_len = 7 + 2; // "monitor" + '\r\n'
  size_t regex_len = strlen(regex);

  if (regex_len > 0) {
    cmd_len += regex_len + 1;
  }

  char cmd[cmd_len + 1]; // +1 for '\0' :facepalm:
  if (regex_len > 0) {
    sprintf(cmd, "monitor %s\r\n", regex);
  } else {
    sprintf(cmd, "monitor\r\n");
  }

  res = mbedtls_ssl_write(&(monitor_ctx->secondary_connection.ssl), (unsigned char *)cmd, cmd_len);
  if (res < 0 || res != cmd_len) {
    atclient_atlogger_log("atclient_start_monitor", ATLOGGER_LOGGING_LEVEL_ERROR, "Failed to send monitor command");
    atclient_free(monitor_ctx);
  } else {
    printf("Sent command\n");
    res = 0;
  }

  return res;
}

int atclient_send_heartbeat(atclient *ctx) {
  int ret = -1;
  unsigned char command[9] = "noop:0\r\n\0";

  ret = mbedtls_ssl_write(&(ctx->secondary_connection.ssl), command, 9);
  if (ret < 0 || ret != 9) {
    atclient_atlogger_log("atclient_start_monitor", ATLOGGER_LOGGING_LEVEL_ERROR, "Failed to send monitor command");
  } else {
    ret = 0;
  }

  return ret;
}

static int parse_notification(atclient_monitor_message *message, char *message_body);
int atclient_read_monitor(atclient *monitor_connection, atclient_monitor_message *message) {
  int ret = -1;

  size_t chunk_size = ATCLIENT_MONITOR_BUFFER_LEN;
  int chunks = 0;
  char *buffer = malloc(chunk_size * 1 * sizeof(char));

  bool done_reading = 0;

  while (done_reading == 0) {
    atclient_atlogger_log("parse_notification", ATLOGGER_LOGGING_LEVEL_DEBUG, "Reading chunk\n");
    if (chunks > 0) {
      buffer = realloc(buffer, chunk_size * chunks * sizeof(char));
    }
    size_t off = chunk_size * chunks++;
    for (int i = 0; i < chunk_size; i++) {
      ret = mbedtls_ssl_read(&monitor_connection->secondary_connection.ssl, (unsigned char *)buffer + off + i, 1);
      if (ret < 0 || buffer[off + i] == '\n') {
        done_reading = 1;
        break;
      }
    }
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
  char *message_body = strtok(NULL, "");

  if (strcmp(message_type, "data") == 0) {
    message->type = MMT_data_response;
    message->data_response = message_body;
  } else if (strcmp(message_type, "notification") == 0) {
    message->type = MMT_notification;
    ret = parse_notification(message, message_body);
    if (ret != 0) {
      atclient_atlogger_log("atclient_read_monitor", ATLOGGER_LOGGING_LEVEL_ERROR, "Failed to parse notification");
    }
  } else if (strcmp(message_type, "error") == 0) {
    message->type = MMT_error_response;
    message->error_response = message_body;
  } else {
    message->type = MMT_none;
    atclient_atlogger_log("atclient_read_monitor", ATLOGGER_LOGGING_LEVEL_ERROR, "Failed to identify message type");
    ret = -1;
  }

  free(buffer);
  return ret;
}
static int parse_notification(atclient_monitor_message *message, char *message_body) {
  int ret = -1;

  cJSON *root = cJSON_Parse(message_body);
  if (root == NULL) {
    cJSON_Delete(root);
    atclient_atlogger_log("parse_notification", ATLOGGER_LOGGING_LEVEL_ERROR, "Failed to parse notification body");
    ret = -1;
    return ret;
  }

  cJSON *key = cJSON_GetObjectItem(root, "key");
  atclient_atkey_from_string(&message->notification.key, key->valuestring, strlen(key->valuestring));

  if (false) { // TODO: if regex doesnt match // do we even need this now?
    atclient_atlogger_log("parse_notification", ATLOGGER_LOGGING_LEVEL_ERROR, "Regex failed to match");
    cJSON_Delete(root);
    atclient_monitor_message_free(message);
    ret = -1;
    return ret;
  }

  cJSON *id = cJSON_GetObjectItem(root, "id");
  message->notification.id = malloc(strlen(id->valuestring) * sizeof(char));
  strcpy(message->notification.id, id->valuestring);

  cJSON *metadata = cJSON_GetObjectItem(root, "metadata");
  if (metadata != NULL) {
    atclient_atkey_metadata_from_cjson_node(&message->notification.key.metadata, metadata);
  }

  cJSON *from = cJSON_GetObjectItem(root, "from");
  atclient_atsign_init(&message->notification.from, from->valuestring);

  cJSON *to = cJSON_GetObjectItem(root, "to");
  atclient_atsign_init(&message->notification.to, to->valuestring);

  cJSON *epochMillis = cJSON_GetObjectItem(root, "epochMillis");
  message->notification.epochMillis = epochMillis->valueint;

  cJSON *messageType = cJSON_GetObjectItem(root, "messageType");
  strncpy(message->notification.messageType, messageType->valuestring, 5);

  cJSON *isEncrypted = cJSON_GetObjectItem(root, "isEncrypted");
  message->notification.isEncrypted = isEncrypted->valueint != 0;

  cJSON *value = cJSON_GetObjectItem(root, "value");
  message->notification.value = malloc(strlen(value->valuestring));
  strcpy(message->notification.value, value->valuestring);

  cJSON *operation = cJSON_GetObjectItem(root, "operation");
  strncpy(message->notification.operation, operation->valuestring, 7);

  cJSON *expiresAt = cJSON_GetObjectItem(root, "expiresAt");
  message->notification.expiresAt = expiresAt->valueint;

  cJSON_Delete(root);
  return ret;
}
