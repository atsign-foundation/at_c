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
    [NMT_text] = "text", // legacy
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
  char id[37]; // uuid v4 + '\0', could be null
  atclient_atkey key; // required
  char *value; // could be null
  enum atclient_notify_operation operation; // 
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

/**
 * @brief send a notification to another atSign. Notifications is a method of sending messages to other atSigns, typically used for real-time communication.
 *
 * @param ctx the atclient context which has already been pkam_authenticated
 * @param params the parameters for the notification. This is where you state the input parameters for the notification to be sent, such as the key, value, etc.
 * @param notification_id the buffer to store the output notification id upon successful completion
 * @return int 0 on success, otherwise failure
 */
int atclient_notify(atclient *ctx, atclient_notify_params *params, char *notification_id);
