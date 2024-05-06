#include "atclient/notify.h"
#include "atclient/connection.h"
#include "atclient/constants.h"
#include "atclient/stringutils.h"
#include "atclient/encryption_key_helpers.h"
#include "cJSON.h"
#include <atchops/uuid.h>
#include <atlogger/atlogger.h>
#include <mbedtls/threading.h>
#include <stdlib.h>
#include <string.h>
#include <sys/time.h>
#include <unistd.h>

#define TAG "notify"

void atclient_notify_params_init(atclient_notify_params *params) {
  params->message_type = NMT_key;
  params->priority = NP_low;
  params->strategy = NS_all;
  params->latest_n = 1;
  params->notifier = ATCLIENT_DEFAULT_NOTIFIER;
  params->notification_expiry = 24 * 60 * 60 * 1000; // 24 hours in milliseconds
}

void atclient_notify_params_free(atclient_notify_params *params) {
  // atclient_atkey_free(&params->key);
  // free(params->value);
  // free(params->notifier);
  return;
}

int atclient_notify(atclient *ctx, atclient_notify_params *params, char *notification_id) {
  int ret = 1;

  // Step 1: calculate the buffer size needed for the protocol command
  size_t bufsize = 6                          // notify
                   + 1                        // :
                   + 8                        // notifier
                   + 1                        // :
                   + strlen(params->notifier) // $notifier
                   + 2                        // \r\n
                   + 1                        // \0
      ;

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
  const size_t metadatalen = atclient_atkey_metadata_protocol_strlen(&params->key.metadata);
  bufsize += metadatalen; // :$metadata

  // atkey parts length
  const size_t atkeylen = atclient_atkey_strlen(&params->key);
  bufsize += atkeylen; // :$atkey

  bufsize += 1; // null terminator

  // Step 2: calculate the ttln
  struct timeval tv;
  ret = gettimeofday(&tv, NULL);
  if (ret != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR,
                 // TODO: get errno
                 "gettimeofday failed with code stored in errno %d\n", ret);
    return ret;
  }

  const unsigned long long ttln =
      (unsigned long long)(tv.tv_sec) * 1000 + (unsigned long long)(tv.tv_usec) / 1000 + params->notification_expiry;

  // Step 3: allocate buffer and populate the full command
  char cmd[bufsize];
  snprintf(cmd, bufsize, "notify");

  char *part;
  size_t offset = strlen(cmd);
  if (params->operation != NO_none) {
    part = atclient_notify_operation_str[params->operation];
    snprintf(cmd + offset, bufsize - offset, ":operation:%s", part);
    offset += strlen(":operation:") + strlen(part);
  }

  if (params->message_type != NMT_none) {
    part = atclient_notify_message_type_str[params->message_type];
    snprintf(cmd + offset, bufsize - offset, ":messageType:%s", part);
    offset += strlen(":messageType:") + strlen(part);
  }

  if (params->priority != NP_none) {
    part = atclient_notify_priority_str[params->priority];
    snprintf(cmd + offset, bufsize - offset, ":priority:%s", part);
    offset += strlen(":priority:") + strlen(part);
  }

  if (params->strategy != NS_none) {
    part = atclient_notify_strategy_str[params->strategy];
    snprintf(cmd + offset, bufsize - offset, ":strategy:%s", part);
    offset += strlen(":strategy:") + strlen(part);
  }

  if (params->notification_expiry > 0) {
    int ttln_len = long_strlen(ttln);
    snprintf(cmd + offset, bufsize - offset, ":ttln:%llu", ttln);
    offset += strlen(":ttln:") + ttln_len;
  }

  size_t metadataolen;
  atclient_atkey_metadata_to_protocol_str(&(params->key.metadata), cmd + offset, metadatalen, &metadataolen);
  if (metadatalen != metadataolen) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR,
                 "calculated metadata length %d but got %d\n", metadatalen, metadataolen);
    return 1;
  }
  offset += metadatalen;

  // ':' before the atkey
  cmd[offset] = ':';
  offset += 1;

  size_t atkeyolen;
  atclient_atkey_to_string(&params->key, cmd + offset, atkeylen, &atkeyolen);
  if (atkeylen != atkeyolen) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR,
                 "calculated atkey length %d but got %d\n", atkeylen, atkeyolen);
    return 1;
  }
  offset += atkeylen;

  if(params->value != NULL)
  {
    // add final :
    cmd[offset] = ':';
    offset += 1;

    // atclient_get_shared_encryption_key_shared_by_me(ctx, &(params->key.sharedwith.str), params->key.)
  }

  // log cmd
  atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_DEBUG, "notify command: %s\n", cmd);

  // if (params->value != NULL) {
  //   snprintf(cmd + offset, bufsize - offset, ":%s", params->value);
  //   offset += strlen(":") + strlen(params->value);
  // }

  // snprintf(cmd + offset, bufsize - offset, "\r\n");
  // offset += strlen("\r\n");

  // Step 4 send the command
  // const size_t recvsize = 1024;
  // unsigned char recv[recvsize];
  // memset(recv, 0, sizeof(unsigned char) * recvsize);
  // size_t recvlen = 0;

  // ret = atclient_connection_send(&ctx->secondary_connection, (const unsigned char *)cmd, offset, recv, recvsize, &recvlen);
  // if (ret != 0) {
  //   atlogger_log("atclient | notify", ATLOGGER_LOGGING_LEVEL_WARN, "atclient_connection_send failed with code %d\n",
  //                ret);
  //   return ret;
  // }
  // // TODO  handle the recv


  return 0;
}
