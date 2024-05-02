#include "atclient/notification.h"
#include "atclient/connection.h"
#include "atclient/constants.h"
#include "atclient/stringutils.h"
#include "cJSON.h"
#include <atchops/uuid.h>
#include <atlogger/atlogger.h>
#include <stdlib.h>
#include <string.h>
#include <sys/time.h>

void atclient_notify_params_init(atclient_notify_params *params) {
  params->message_type = NMT_key;
  params->priority = NP_low;
  params->strategy = NS_all;
  params->latest_n = 1;
  params->notifier = ATCLIENT_DEFAULT_NOTIFIER;
  params->notification_expiry = 24 * 60 * 60 * 1000; // 24 hours in milliseconds
}

void atclient_notify_params_free(atclient_notify_params *params) {
  atclient_atkey_free(&params->key);
  free(params->value);
  free(params->notifier);
}

int atclient_notify(atclient *ctx, atclient_notify_params *params) {
  int res = 1;
  // Step 1 calculate the buffer size needed for the protocol command
  size_t bufsize = 6 + 1 + 2 + 1 + 36 + 3 +              // "notify:id:" + $uuid + trailing '\r\n\0'
                   1 + 8 + 1 + strlen(params->notifier); // ":notifier:$notifier"

  // minimum viable: notify:update:key:value -> id
  // TODO: check for bad input in params struct since we don't provide the best helper functions
  // and add valid ones to bufsize

  if (params->operation != NO_none) {
    bufsize += 1 + 6; // ":update" | ":delete"
  }

  if (params->message_type != NMT_none) {
    bufsize += 1 + 11 + 1 + 4; // ":messageType" + ":text" | ":key"
  }

  if (params->priority != NP_none) {
    bufsize += 1 + 8 + 1 + 6; // ":priority" + ":low" | ":medium" | ":high"
  }

  if (params->strategy != NS_none) {
    bufsize += 1 + 8 + 1 + 6; // ":strategy" + ":all" | ":latest"
  }

  if (params->notification_expiry > 0) {
    bufsize += 1 + 4 + 1 + // ":ttln:"
               20;         // epochMillis (20 digits covers all 2^64 of unsigned long long, good for 300,000+ years)
  }

  if (params->value != NULL) {
    bufsize += 1 + strlen(params->value); // :$value
  }

  // add metadata fragment length
  size_t metadatalen = atclient_atkey_metadata_protocol_strlen(&params->key.metadata);
  bufsize += metadatalen;

  // atkey parts length
  size_t atkeylen = atclient_atkey_strlen(&params->key);
  bufsize += 1 + atkeylen; // :$atkey

  // Step 2 generate / retrieve values which could potentially fail
  res = atchops_uuid_init();
  if (res != 0) {
    atlogger_log("atclient | notification", ATLOGGER_LOGGING_LEVEL_WARN,
                          "atchops_uuid_init failed with code %d\n", res);
    return res;
  }

  // careful about when this is called, since it will write a null terminator to the 37th char
  res = atchops_uuid_generate(params->id, 37);
  if (res != 0) {
    atlogger_log("atclient | notification", ATLOGGER_LOGGING_LEVEL_WARN,
                          "atchops_uuid_generate failed with code %d\n", res);
    return res;
  }

  struct timeval tv;
  res = gettimeofday(&tv, NULL);
  if (res != 0) {
    atlogger_log("atclient | notification", ATLOGGER_LOGGING_LEVEL_WARN,
                          // TODO: get errno
                          "gettimeofday failed with code stored in errno %d\n", res);
    return res;
  }

  unsigned long long ttln =
      (unsigned long long)(tv.tv_sec) * 1000 + (unsigned long long)(tv.tv_usec) / 1000 + params->notification_expiry;

  // Step 3 allocate the buffer and populate the full command
  char cmd[bufsize];
  snprintf(cmd, bufsize, "notify:id:%s", params->id);
  // now overwrite the '\0' at the tail of params->id

  const char *part;
  size_t off = 46;
  if (params->operation != NO_none) {
    part = atclient_notify_operation_str[params->operation];
    snprintf(cmd + off, bufsize - off, ":%s", part);
    off += 1 + strlen(part);
  }

  if (params->message_type != NMT_none) {
    part = atclient_notify_message_type_str[params->message_type];
    snprintf(cmd + off, bufsize - off, ":messageType:%s", part);
    off += 13 + strlen(part);
  }

  if (params->priority != NP_none) {
    part = atclient_notify_priority_str[params->priority];
    snprintf(cmd + off, bufsize - off, ":priority:%s", part);
    off += 10 + strlen(part);
  }

  if (params->strategy != NS_none) {
    part = atclient_notify_strategy_str[params->strategy];
    snprintf(cmd + off, bufsize - off, ":strategy:%s", part);
    off += 10 + strlen(part);
  }

  if (params->notification_expiry > 0) {
    int ttln_len = long_strlen(ttln);
    snprintf(cmd + off, bufsize - off, ":ttln:%llu", ttln);
    off += 6 + ttln_len;
  }

  size_t metadataolen;
  atclient_atkey_metadata_to_protocol_str(&params->key.metadata, cmd + off, metadatalen, &metadataolen);
  if (metadatalen != metadataolen) {
    // TODO: error
    return 1;
  }
  off += metadatalen;

  // ':' before the atkey
  cmd[off] = ':';
  off += 1;

  size_t atkeyolen;
  atclient_atkey_to_string(&params->key, cmd + off, atkeylen, &atkeyolen);
  if (atkeylen != atkeyolen) {
    // TODO: error
    return 1;
  }
  off += atkeylen;

  if (params->value != NULL) {
    snprintf(cmd + off, bufsize - off, ":%s", params->value);
    off += 1 + strlen(params->value);
  }

  snprintf(cmd + off, bufsize - off, "\r\n");
  off += 2;

  // Step 4 send the command
  const size_t recvsize = 4096;
  unsigned char recv[recvsize];
  memset(recv, 0, sizeof(unsigned char) * recvsize);
  size_t recvlen = 0;

  res = atclient_connection_send(&ctx->secondary_connection, (const unsigned char *)cmd, off, recv, recvsize, &recvlen);
  if (res != 0) {
    atlogger_log("atclient | notify", ATLOGGER_LOGGING_LEVEL_WARN,
                          "atclient_connection_send failed with code %d\n", res);
    return res;
  }
  // TODO  handle the recv
  return 0;
}

int atclient_monitor(atclient *ctx, const atclient_monitor_params *params) {
  int res = 1;
  size_t cmd_len = 7 + 1; // "monitor" + '\0'
  size_t regex_len = strlen(params->regex);
  if (regex_len > 0) {
    cmd_len += regex_len + 1;
  }

  char cmd[cmd_len];
  if (regex_len > 0) {
    snprintf(cmd, cmd_len, "%s %s", "monitor", params->regex);
  } else {
    snprintf(cmd, cmd_len, "%s", "monitor");
  }

  // Send the monitor command
  // poll for responses
  // find \n to
  res = mbedtls_ssl_write(&ctx->secondary_connection.ssl, (unsigned char *)cmd, cmd_len);

  char *buffer = calloc(0, sizeof(char));
  size_t buffer_size, buffer_pos = 0;
  int newline_pos = -1;
  bool bad_read = 0;

  while (true) {
    // Allocate another buffer and read into it
    buffer_size = buffer_pos + ATCLIENT_MONITOR_BUFFER_LEN;
    buffer = realloc(buffer, buffer_size * sizeof(char));
    res = mbedtls_ssl_read(&ctx->secondary_connection.ssl, (unsigned char *)buffer + buffer_pos,
                           ATCLIENT_MONITOR_BUFFER_LEN);

    if (res < 0) {
      bad_read = 1;
    }

    // go through the freshly read buffer and look for a newline
    buffer_pos += res;
    for (int i = 0; i < res; i++) {
      if (buffer[i] == '\n') {
        newline_pos = i;
      }
    }

    // if there's no newline found yet, keep reading
    if (newline_pos < 0) {
      continue;
    }

    // if we got a bad read, then skip this entire message
    if (bad_read != 0) {
      bad_read = 0;
      goto reset_buffer;
    }

    // compute the carry over (everything read after the newline)
    size_t carry_size = 0;
    size_t carry_pos = newline_pos + 1;

    // Check if we got a non-notification
    if (strncmp(buffer, "notification:", 13) != 0) {
      atlogger_log(
          "monitor", ATLOGGER_LOGGING_LEVEL_WARN,
          "Parsed a non-notification, avoid potential race conditions by using a separate atclient for monitor");
      goto reset_buffer;
    }

    // read in the notification
    atclient_atnotification notification;
    buffer[newline_pos] = '\0';
    cJSON *root = cJSON_Parse(buffer);

    // ensure that the notification is valid json
    if (root == NULL) {
      cJSON_Delete(root);
      goto reset_buffer;
    }

    // read each of the values into the notification struct
    cJSON *key = cJSON_GetObjectItem(root, "key");
    atclient_atkey_from_string(&notification.key, key->valuestring, strlen(key->valuestring));

    if (false) { // TODO: if regex doesnt match
      cJSON_Delete(root);
      atclient_atkey_free(&notification.key);
      goto reset_buffer;
    }

    cJSON *id = cJSON_GetObjectItem(root, "id");
    notification.id = malloc(strlen(id->valuestring) * sizeof(char));
    strcpy(notification.id, id->valuestring);

    cJSON *metadata = cJSON_GetObjectItem(root, "metadata");
    if (metadata != NULL) {
      atclient_atkey_metadata_from_cjson_node(&notification.key.metadata, metadata);
    }

    cJSON *from = cJSON_GetObjectItem(root, "from");
    atclient_atsign_init(&notification.from, from->valuestring);

    cJSON *to = cJSON_GetObjectItem(root, "to");
    atclient_atsign_init(&notification.to, to->valuestring);

    cJSON *epochMillis = cJSON_GetObjectItem(root, "epochMillis");
    notification.epochMillis = epochMillis->valueint;

    cJSON *messageType = cJSON_GetObjectItem(root, "messageType");
    strncpy(notification.messageType, messageType->valuestring, 5);

    cJSON *isEncrypted = cJSON_GetObjectItem(root, "isEncrypted");
    notification.isEncrypted = isEncrypted->valueint != 0;

    cJSON *value = cJSON_GetObjectItem(root, "value");
    notification.value = malloc(strlen(value->valuestring));
    strcpy(notification.value, value->valuestring);

    cJSON *operation = cJSON_GetObjectItem(root, "operation");
    strncpy(notification.operation, operation->valuestring, 7);

    cJSON *expiresAt = cJSON_GetObjectItem(root, "expiresAt");
    notification.expiresAt = expiresAt->valueint;

    // call the handler callback with the notification
    params->handler(&notification);

    // free the notification
    cJSON_Delete(root);
    free(notification.id);
    atclient_atkey_free(&notification.key);
    atclient_atsign_free(&notification.from);
    atclient_atsign_free(&notification.to);
    free(notification.value);

    // if we have something to carry over, copy it to the start of the next buffer
    if (carry_pos < buffer_size) {
      carry_size = buffer_size - carry_pos;
      memcpy(buffer, buffer + carry_pos, carry_size);
    }
  reset_buffer:
    buffer = realloc(buffer, carry_size * sizeof(char));
    newline_pos = -1;
  }
exit:
  return res;
}
