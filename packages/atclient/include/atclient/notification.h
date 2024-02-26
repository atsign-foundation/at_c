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

bool atclient_notify_params_is_key_initialized(atclient_notify_params *params);
bool atclient_notify_params_is_id_initialized(atclient_notify_params *params);
bool atclient_notify_params_is_operation_initialized(atclient_notify_params *params);
bool atclient_notify_params_is_message_type_initialized(atclient_notify_params *params);
bool atclient_notify_params_is_priority_initialized(atclient_notify_params *params);
bool atclient_notify_params_is_strategy_initialized(atclient_notify_params *params);
bool atclient_notify_params_is_latest_n_initialized(atclient_notify_params *params);
bool atclient_notify_params_is_notifier_initialized(atclient_notify_params *params);
bool atclient_notify_params_is_ttln_initialized(atclient_notify_params *params);
bool atclient_notify_params_is_is_public_initialized(atclient_notify_params *params);
bool atclient_notify_params_is_value_initialized(atclient_notify_params *params);

int atclient_notify_params_set_key(atclient_notify_params *params, const atclient_atkey *key);
int atclient_notify_params_setid(atclient_notify_params *params, const char *id, const size_t id_len);
int atclient_notify_params_setoperation(atclient_notify_params *params, const char *operation,
                                        const size_t operation_len);
int atclient_notify_params_setmessage_type(atclient_notify_params *params, const char *message_type,
                                           const size_t message_type_len);
int atclient_notify_params_setpriority(atclient_notify_params *params, const char *priority, const size_t priority_len);
int atclient_notify_params_setstrategy(atclient_notify_params *params, const char *strategy, const size_t strategy_len);
int atclient_notify_params_setlatest_n(atclient_notify_params *params, const char *latest_n, const size_t latest_n_len);
int atclient_notify_params_setnotifier(atclient_notify_params *params, const char *notifier, const size_t notifier_len);
int atclient_notify_params_setttln(atclient_notify_params *params, const char *ttln, const size_t ttln_len);
int atclient_notify_params_setis_public(atclient_notify_params *params, const char *is_public,
                                        const size_t is_public_len);
int atclient_notify_params_setvalue(atclient_notify_params *params, const char *value, const size_t value_len);

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
