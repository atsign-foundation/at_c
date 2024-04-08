#ifndef NOTIFICATION_H
#define NOTIFICATION_H

#include "atclient.h"
#include "atkey.h"

// For sending notifications
enum atclient_notify_operation { NO_none, NO_update, NO_delete };
static const char *atclient_notify_operation_str[] = {
    [NO_update] = "update",
    [NO_delete] = "delete",
};

enum atclient_notify_message_type { NMT_none, NMT_key, NMT_text };
static const char *atclient_notify_message_type_str[] = {
    [NMT_key] = "key",
    [NMT_text] = "text",
};

enum atclient_notify_priority { NP_none, NP_low, NP_medium, NP_high };
static const char *atclient_notify_priority_str[] = {
    [NP_low] = "low",
    [NP_medium] = "medium",
    [NP_high] = "high",
};

enum atclient_notify_strategy { NS_none, NS_all, NS_latest };
static const char *atclient_notify_strategy_str[] = {
    [NS_all] = "all",
    [NS_latest] = "latest",
};

typedef struct atclient_notify_params {
  char id[37]; // uuid v4 + '\0'
  atclient_atkey key;
  char *value;
  enum atclient_notify_operation operation;
  enum atclient_notify_message_type message_type;
  enum atclient_notify_priority priority;
  enum atclient_notify_strategy strategy;
  int latest_n;
  char *notifier;
  unsigned long notification_expiry;
} atclient_notify_params;
// TODO: add shared with encryption key

void atclient_notify_params_init(atclient_notify_params *params);
void atclient_notify_params_free(atclient_notify_params *params);

int atclient_notify(atclient *ctx, atclient_notify_params *params);
// Receiving notifications
typedef struct atclient_atnotification {
  char *id;
  atclient_atsign from;
  atclient_atsign to;
  atclient_atkey key;
  char *value;
  char operation[7]; // update | delete
  size_t epochMillis;
  char messageType[5]; // key | text (deprecated)
  bool isEncrypted;
  size_t expiresAt;
} atclient_atnotification;

typedef void(atclient_monitor_handler)(const atclient_atnotification *notification);
typedef struct atclient_monitor_params {
  char *regex;
  atclient_monitor_handler *handler;
} atclient_monitor_params;

int atclient_notify(atclient *ctx, atclient_notify_params *notification);
int atclient_monitor(atclient *ctx, const atclient_monitor_params *params);

#endif
