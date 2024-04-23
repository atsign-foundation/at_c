#include "atclient/notify.h"
#include "atclient/connection.h"
#include "atclient/constants.h"
#include "atclient/stringutils.h"
#include "cJSON.h"
#include <atchops/uuid.h>
#include <atlogger/atlogger.h>
#include <mbedtls/threading.h>
#include <stdlib.h>
#include <string.h>
#include <sys/time.h>
#include <unistd.h>

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
    atclient_atlogger_log("atclient | notification", ATLOGGER_LOGGING_LEVEL_WARN,
                          "atchops_uuid_init failed with code %d\n", res);
    return res;
  }

  // careful about when this is called, since it will write a null terminator to the 37th char
  res = atchops_uuid_generate(params->id, 37);
  if (res != 0) {
    atclient_atlogger_log("atclient | notification", ATLOGGER_LOGGING_LEVEL_WARN,
                          "atchops_uuid_generate failed with code %d\n", res);
    return res;
  }

  struct timeval tv;
  res = gettimeofday(&tv, NULL);
  if (res != 0) {
    atclient_atlogger_log("atclient | notification", ATLOGGER_LOGGING_LEVEL_WARN,
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
  const size_t recvlen = 4096;
  unsigned char recv[recvlen];
  memset(recv, 0, sizeof(unsigned char) * recvlen);
  size_t recvolen = 0;

  res = atclient_connection_send(&ctx->secondary_connection, (const unsigned char *)cmd, off, recv, recvlen, &recvolen);
  if (res != 0) {
    atclient_atlogger_log("atclient | notify", ATLOGGER_LOGGING_LEVEL_WARN,
                          "atclient_connection_send failed with code %d\n", res);
    return res;
  }
  // TODO  handle the recv
  return 0;
}
