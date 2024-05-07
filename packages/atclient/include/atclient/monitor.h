#ifndef ATCLIENT_MONITOR_H
#define ATCLIENT_MONITOR_H

#include <atclient/atclient.h>
#include <atclient/atkey.h>
#include <atclient/atsign.h>
#include <atclient/constants.h>

enum atclient_monitor_message_type {
  ATCLIENT_MONITOR_MESSAGE_TYPE_NONE,
  ATCLIENT_MONITOR_MESSAGE_TYPE_NOTIFICATION,
  ATCLIENT_MONITOR_MESSAGE_TYPE_DATA,
  ATCLIENT_MONITOR_MESSAGE_TYPE_ERROR
};

// Receiving notifications
typedef struct atclient_atnotification {
  char id[37];
  char from[ATCLIENT_ATSIGN_FULL_LEN];
  char to[ATCLIENT_ATSIGN_FULL_LEN];
  atclient_atkey key;
  char *value;
  char operation[7]; // update | delete
  size_t epochMillis;
  char messageType[5]; // key | text (deprecated)
  bool isEncrypted;
  size_t expiresAt;
} atclient_atnotification;

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

void atclient_monitor_init(atclient *monitor_ctx);
void atclient_monitor_free(atclient *monitor_ctx);

/* @brief Create a new atServer connection and send the monitor verb
 * @param monitor the atclient context for the monitor connection
 * @param root_host the hostname of the root server
 * @param root_port the port of the root server
 * @param atsign the atsign
 * @param atkeys the atkeys of the atsign
 * @param regex the regex to match the keys
 * @return 0 on success, non-zero on error
 */
int atclient_monitor_start_connection(atclient *monitor, const char *root_host, const int root_port, const char *atsign, const atclient_atkeys *atkeys, const char *regex);

/* @brief Send a heartbeat on the monitor connection
 * @param ctx the atclient context for the monitor connection
 * @return 0 on success, non-zero on error
 *
 * @note Ideally this is scheduled to be sent every 30 seconds
 * @note this is different than a normal noop command, since we don't listen for the response from the server
 */
int atclient_monitor_send_heartbeat(atclient *ctx);

/* @brief Read a notification from the monitor connection into message
 * @param ctx the atclient context for the monitor connection
 * @param notification the notification to be read
 * @return 0 on success, non-zero on error
 *
 * @note Message may be a notification or a data response, check message.is_notification to know which one it is
 */
int atclient_monitor_read(atclient *monitor_connection, atclient_monitor_message *message);

#endif
