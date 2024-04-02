#include "atclient/monitor.h"
#include "atclient/atclient.h"
#include "atclient/connection.h"
#include "atclient/constants.h"
#include "cJSON/cJSON.h"
#include <atchops/uuid.h>
#include <atlogger/atlogger.h>
#include <mbedtls/threading.h>
#include <stdlib.h>
#include <string.h>
#include <sys/time.h>
#include <unistd.h>

int atclient_start_monitor(atclient *monitor_connection, const char *root_host, const int root_port,
                           const atclient_atsign atsign, const atclient_atkeys atkeys, const char *regex) {
  int res = 1;
  atclient_init(monitor_connection);

  atclient_connection root_connection;
  atclient_connection_init(&root_connection);
  atclient_connection_connect(&root_connection, root_host, root_port);

  res = atclient_pkam_authenticate(monitor_connection, &root_connection, atkeys, atsign.atsign, strlen(atsign.atsign));
  atclient_connection_free(&root_connection);

  if (res != 0) {
    atclient_atlogger_log("atclient_start_monitor", ATLOGGER_LOGGING_LEVEL_ERROR, "Failed to pkam authenticate");
    atclient_free(monitor_connection);
  }

  size_t cmd_len = 7 + 2; // "monitor" + '\r\n'
  size_t regex_len = strlen(regex);

  if (regex_len > 0) {
    cmd_len += regex_len + 1;
  }

  char cmd[cmd_len];
  if (regex_len > 0) {
    snprintf(cmd, cmd_len, "monitor %s\r\n", regex);
  } else {
    snprintf(cmd, cmd_len, "monitor\r\n");
  }

  res = mbedtls_ssl_write(&monitor_connection->secondary_connection.ssl, (unsigned char *)cmd, cmd_len);

  if (res < 0 || res != cmd_len) {
    atclient_atlogger_log("atclient_start_monitor", ATLOGGER_LOGGING_LEVEL_ERROR, "Failed to send monitor command");
    atclient_free(monitor_connection);
  }

  return res;
}

// printf("res: %d\n", res);
//
// char *buffer = calloc(0, sizeof(char));
// size_t buffer_size, buffer_pos = 0;
// int newline_pos = -1;
// bool bad_read = 0;
//
// while (true) {
//   printf("Starting read loop\n");
//   // Allocate another buffer and read into it
//
//   buffer_size = buffer_pos + ATCLIENT_MONITOR_BUFFER_LEN;
//   buffer = realloc(buffer, buffer_size * sizeof(char));
//   res = mbedtls_ssl_read(&atclient.secondary_connection.ssl, (unsigned char *)buffer + buffer_pos,
//                          ATCLIENT_MONITOR_BUFFER_LEN);
//
//   printf("Read %d bytes\n", res);
//   if (res < 0) {
//     bad_read = 1;
//     printf("Bad read\n");
//     return 1;
//   }
//
//   // go through the freshly read buffer and look for a newline
//   buffer_pos += res;
//   for (int i = 0; i < res; i++) {
//     if (buffer[i] == '\n') {
//       newline_pos = i;
//     }
//   }
//
//   // if there's no newline found yet, keep reading
//   if (newline_pos < 0) {
//     continue;
//   }
//
//   // if we got a bad read, then skip this entire message
//   if (bad_read != 0) {
//     bad_read = 0;
//     goto reset_buffer;
//   }
//
//   // compute the carry over (everything read after the newline)
//   size_t carry_size = 0;
//   size_t carry_pos = newline_pos + 1;
//
//   // Check if we got a non-notification
//   if (strncmp(buffer, "notification:", 13) != 0) {
//     atclient_atlogger_log(
//         "monitor", ATLOGGER_LOGGING_LEVEL_WARN,
//         "Parsed a non-notification, avoid potential race conditions by using a separate atclient for monitor");
//     goto reset_buffer;
//   }
//
//   // read in the notification
//   atclient_atnotification notification;
//   buffer[newline_pos] = '\0';
//   cJSON *root = cJSON_Parse(buffer);
//
//   // ensure that the notification is valid json
//   if (root == NULL) {
//     cJSON_Delete(root);
//     goto reset_buffer;
//   }
//
//   // read each of the values into the notification struct
//   cJSON *key = cJSON_GetObjectItem(root, "key");
//   atclient_atkey_from_string(&notification.key, key->valuestring, strlen(key->valuestring));
//
//   if (false) { // TODO: if regex doesnt match
//     cJSON_Delete(root);
//     atclient_atkey_free(&notification.key);
//     goto reset_buffer;
//   }
//
//   cJSON *id = cJSON_GetObjectItem(root, "id");
//   notification.id = malloc(strlen(id->valuestring) * sizeof(char));
//   strcpy(notification.id, id->valuestring);
//
//   cJSON *metadata = cJSON_GetObjectItem(root, "metadata");
//   if (metadata != NULL) {
//     atclient_atkey_metadata_from_cjson_node(&notification.key.metadata, metadata);
//   }
//
//   cJSON *from = cJSON_GetObjectItem(root, "from");
//   atclient_atsign_init(&notification.from, from->valuestring);
//
//   cJSON *to = cJSON_GetObjectItem(root, "to");
//   atclient_atsign_init(&notification.to, to->valuestring);
//
//   cJSON *epochMillis = cJSON_GetObjectItem(root, "epochMillis");
//   notification.epochMillis = epochMillis->valueint;
//
//   cJSON *messageType = cJSON_GetObjectItem(root, "messageType");
//   strncpy(notification.messageType, messageType->valuestring, 5);
//
//   cJSON *isEncrypted = cJSON_GetObjectItem(root, "isEncrypted");
//   notification.isEncrypted = isEncrypted->valueint != 0;
//
//   cJSON *value = cJSON_GetObjectItem(root, "value");
//   notification.value = malloc(strlen(value->valuestring));
//   strcpy(notification.value, value->valuestring);
//
//   cJSON *operation = cJSON_GetObjectItem(root, "operation");
//   strncpy(notification.operation, operation->valuestring, 7);
//
//   cJSON *expiresAt = cJSON_GetObjectItem(root, "expiresAt");
//   notification.expiresAt = expiresAt->valueint;
//
//   // free the notification
//   cJSON_Delete(root);
//   free(notification.id);
//   atclient_atkey_free(&notification.key);
//   atclient_atsign_free(&notification.from);
//   atclient_atsign_free(&notification.to);
//   free(notification.value);
//
//   // if we have something to carry over, copy it to the start of the next buffer
//   if (carry_pos < buffer_size) {
//     carry_size = buffer_size - carry_pos;
//     memcpy(buffer, buffer + carry_pos, carry_size);
//   }
// reset_buffer:
//   buffer = realloc(buffer, carry_size * sizeof(char));
//   newline_pos = -1;
// }
// exit : return res;
// }
