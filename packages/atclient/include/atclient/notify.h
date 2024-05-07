#include "atclient.h"
#include "atkey.h"

// For sending notifications
enum atclient_notify_operation {
  ATCLIENT_NOTIFY_OPERATION_NONE,
  ATCLIENT_NOTIFY_OPERATION_UPDATE,
  ATCLIENT_NOTIFY_OPERATION_DELETE
};

static const char *atclient_notify_operation_str[] = {
    [ATCLIENT_NOTIFY_OPERATION_UPDATE] = "update",
    [ATCLIENT_NOTIFY_OPERATION_DELETE] = "delete",
};

enum atclient_notify_message_type {
  ATCLIENT_NOTIFY_MESSAGE_TYPE_NONE,
  ATCLIENT_NOTIFY_MESSAGE_TYPE_KEY,
  ATCLIENT_NOTIFY_MESSAGE_TYPE_TEXT
};

static const char *atclient_notify_message_type_str[] = {
    [ATCLIENT_NOTIFY_MESSAGE_TYPE_KEY] = "key",
    [ATCLIENT_NOTIFY_MESSAGE_TYPE_TEXT] = "text", // legacy
};

enum atclient_notify_priority {
  ATCLIENT_NOTIFY_PRIORITY_NONE,
  ATCLIENT_NOTIFY_PRIORITY_LOW,
  ATCLIENT_NOTIFY_PRIORITY_MEDIUM,
  ATCLIENT_NOTIFY_PRIORITY_HIGH
};

static const char *atclient_notify_priority_str[] = {
    [ATCLIENT_NOTIFY_PRIORITY_LOW] = "low",
    [ATCLIENT_NOTIFY_PRIORITY_MEDIUM] = "medium",
    [ATCLIENT_NOTIFY_PRIORITY_HIGH] = "high",
};

enum atclient_notify_strategy {
  ATCLIENT_NOTIFY_STRATEGY_NONE,
  ATCLIENT_NOTIFY_STRATEGY_ALL,
  ATCLIENT_NOTIFY_STRATEGY_LATEST
};
static const char *atclient_notify_strategy_str[] = {
    [ATCLIENT_NOTIFY_STRATEGY_ALL] = "all",
    [ATCLIENT_NOTIFY_STRATEGY_LATEST] = "latest",
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
  char *sharedenckeybase64;
} atclient_notify_params;

void atclient_notify_params_init(atclient_notify_params *params);
void atclient_notify_params_create(atclient_notify_params *params, enum atclient_notify_operation operation,
                                   atclient_atkey *atkey, char *value);
void atclient_notify_params_free(atclient_notify_params *params);

int atclient_notify(atclient *ctx, atclient_notify_params *params);
