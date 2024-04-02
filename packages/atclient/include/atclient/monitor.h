#ifndef NOTIFICATION_H
#define NOTIFICATION_H

#include "atclient.h"
#include "atkey.h"

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

enum atclient_monitor_message_type { MMT_none, MMT_notification, MMT_data_response, MMT_error_response };

typedef struct atclient_monitor_message {
  enum atclient_monitor_message_type type;
  union {
    atclient_atnotification notification; // when is_notification is true
    char *data_response;                  // message of the data response (e.g. "ok", when "data:ok" is received)
    char *error_response;                 // message of the error_response
  };
} atclient_monitor_message;

/* @brief Create a new atServer connection and send the monitor verb
 * @param ctx the atclient context for the monitor connection
 * @param root_host the hostname of the root server
 * @param root_port the port of the root server
 * @param atsign the atsign
 * @param atkeys the atkeys of the atsign
 * @param regex the regex to match the keys
 * @return 0 on success, non-zero on error
 */
int atclient_start_monitor(atclient *monitor_connection, const char *root_host, const int root_port,
                           const atclient_atsign *atsign, const atclient_atkeys *atkeys, const char *regex);

/* @brief Send a heartbeat on the monitor connection
 * @param ctx the atclient context for the monitor connection
 * @return 0 on success, non-zero on error
 *
 * @note Ideally this is scheduled to be sent every 30 seconds
 */
int atclient_send_heartbeat(atclient *ctx);

/* @brief Read a notification from the monitor connection into message
 * @param ctx the atclient context for the monitor connection
 * @param notification the notification to be read
 * @return 0 on success, non-zero on error
 *
 * @note Message may be a notification or a data response, check message.is_notification to know which one it is
 */
int atclient_read_monitor(atclient *monitor_connection, atclient_monitor_message *message);

#endif
