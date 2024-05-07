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

void atclient_monitor_message_init(atclient_monitor_message *message);
void atclient_monitor_message_free(atclient_monitor_message *message);

void atclient_monitor_init(atclient *monitor_conn);
void atclient_monitor_free(atclient *monitor_conn);

/**
 * @brief Onboards the monitor_connection and starts the monitoring connection.
 *
 * @param monitor_conn ctx the atclient context for the monitor connection
 * @param root_host root_host the hostname of the root server
 * @param root_port root_port the port of the root server
 * @param atsign atsign the atSign (e.g. \"@bob\", )
 * @param atkeys atkeys the populated atKeys of the atSign
 * @param regex atsign the atsign
 * @return int 0 on success
 */
int atclient_start_monitor(atclient *monitor_conn, const char *root_host, const int root_port, const char *atsign,
                           const atclient_atkeys *atkeys, const char *regex, const size_t regexlen);

/**
 * @brief Send a heartbeat on the monitor connection
 * @param monitor_conn the atclient context for the monitor connection
 * @return 0 on success, non-zero on error
 *
 * @note Ideally this is scheduled to be sent every 30 seconds
 * @note this is different than a normal noop command, since we don't listen for the response from the server
 * @note It is the responsibility of the caller to ensure that the monitor connection is still alive
 */
int atclient_send_heartbeat(atclient *monitor_conn);

/**
 * @brief Read a notification from the monitor connection into message
 * @param monitor_conn the atclient context for the monitor connection
 * @param message the notification to be read
 * @return 0 on success, non-zero on error
 *
 * @note Message may be a notification or a data response, check message.is_notification to know which one it is
 */
int atclient_read_monitor(atclient *monitor_conn, atclient_monitor_message *message);

#endif
