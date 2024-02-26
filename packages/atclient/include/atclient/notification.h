#ifndef NOTIFICATION_H
#define NOTIFICATION_H

#include "atclient.h"
#include "atkey.h"
#include "atstr.h"
#include "metadata.h"

#define ATCLIENT_MONITOR_VERB "monitor"
#define ATCLIENT_MONITOR_VERB_LEN 7
// For sending notifications

enum atclient_notify_operation { NO_update, NO_delete };
static const char *atclient_notify_operation_str[] = {
    [NO_update] = "update",
    [NO_delete] = "delete",
};

enum atclient_notify_message_type { NMT_key, NMT_text };
static const char *atclient_notify_message_type_str[] = {
    [NMT_key] = "key",
    [NMT_text] = "text",
};

enum atclient_notify_priority { NP_low, NP_medium, NP_high };
static const char *notify_priority_str[] = {
    [NP_low] = "low",
    [NP_medium] = "medium",
    [NP_high] = "high",
};

enum atclient_notify_strategy { NS_all, NS_latest };
static const char *atclient_notify_strategy_str[] = {
    [NS_all] = "all",
    [NS_latest] = "latest",
};

typedef struct atclient_notify_params {
  char initialized[2];
  atclient_atstr id; // will be a generated uuid v4 if not provided
  atclient_atstr operation;
  atclient_atstr message_type;
  atclient_atstr priority;
  atclient_atstr strategy;
  atclient_atstr latest_n;
  atclient_atstr notifier;
  atclient_atstr ttln;
  atclient_atkey key;
  /* atclient_atkey_metadata metadata ; */
  atclient_atstr is_public;
  atclient_atstr value;
} atclient_notify_params;

// This macro function applies another macro function to each atstr in atclient_notify_params
#define FOREACH_NOTIFY_PARAMS_ATSTR_DO(_)                                                                              \
  _(id)                                                                                                                \
  _(operation)                                                                                                         \
  _(message_type)                                                                                                      \
  _(priority)                                                                                                          \
  _(strategy)                                                                                                          \
  _(latest_n)                                                                                                          \
  _(notifier)                                                                                                          \
  _(ttln)                                                                                                              \
  _(is_public)                                                                                                         \
  _(value)

// all is_X_initialized functions for atclient_notify_params
#define DECLARE_IS_INITIALIZED(X) bool atclient_notify_params_is_##X##_initialized(atclient_notify_params *params);
bool atclient_notify_params_is_key_initialized(atclient_notify_params *params);
FOREACH_NOTIFY_PARAMS_ATSTR_DO(DECLARE_IS_INITIALIZED);
#undef DECLARE_IS_INITIALIZED

// all set_X functions for atclient_notify_params
#define DECLARE_SET_ATSTR(X)                                                                                           \
  int atclient_notify_params_set##X(atclient_notify_params *params, const char *X, const size_t X##_len);
int atclient_notify_params_set_key(atclient_notify_params *params, const atclient_atkey *key);
FOREACH_NOTIFY_PARAMS_ATSTR_DO(DECLARE_SET_ATSTR);
#undef DECLARE_SET_ATSTR

#undef FOREACH_NOTIFY_PARAMS_ATSTR_DO

// Receiving notifications
typedef struct atclient_atnotification {
  atclient_atstr id;
  atclient_atsign from;
  atclient_atsign to;
  atclient_atkey key;
  atclient_atstr value;
  char operation[7]; // update | delete
  size_t epochMillis;
  char messageType[5]; // key | text (deprecated)
  bool isEncrypted;
} atclient_atnotification;

typedef void(atclient_monitor_handler)(const atclient_atnotification *notification);
typedef struct atclient_monitor_params {
  atclient_atstr regex;
  atclient_monitor_handler *handler;
} atclient_monitor_params;

int atclient_notification_params_for_update_init(atclient_notify_params *params);
int atclient_notification_params_free(atclient_notify_params *params);

// TODO: add shared with encryption key
int atclient_notify(const atclient *ctx, atclient_notify_params *notification);
int atclient_monitor(const atclient *ctx, const atclient_monitor_params *params);

#endif
