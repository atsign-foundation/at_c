#ifndef ATCLIENT_MONITOR_H
#define ATCLIENT_MONITOR_H

#include "atclient/atclient.h"
#include "atclient/atkey.h"
#include "atclient/atnotification.h"
#include <stdbool.h>

/**
 * @brief Represents a message received from the monitor connection, typically derived from the prefix of the response
 * (e.g. "data:ok"'s message type would be "data" = ATCLIENT_MONITOR_MESSAGE_TYPE_DATA_RESPONSE)
 */
enum atclient_monitor_response_type {
  // the following 4 enums help indicate what type of message was received from the monitor connection and which field
  // of the union to access
  ATCLIENT_MONITOR_MESSAGE_TYPE_NONE,
  ATCLIENT_MONITOR_MESSAGE_TYPE_NOTIFICATION,   // indicates caller to access `notification` from the union
  ATCLIENT_MONITOR_MESSAGE_TYPE_DATA_RESPONSE,  // indicates caller to access `data_response` from the union
  ATCLIENT_MONITOR_MESSAGE_TYPE_ERROR_RESPONSE, // indicates caller to access `error_response` from the union

  // the following 3 enums help indicate what type of error occurred when reading from the monitor connection, you will
  // expect one of these enums along with a non-zero return value from atclient_monitor_read
  ATCLIENT_MONITOR_ERROR_READ, // could be a read timeout or some other error, indicates the caller to access
                               // `error_read` from the union
  ATCLIENT_MONITOR_ERROR_PARSE_NOTIFICATION,
  ATCLIENT_MONITOR_ERROR_DECRYPT_NOTIFICATION,
};

// Represents error information when `ATCLIENT_MONITOR_ERROR_READ` is the message type given by atclient_monitor_read
typedef struct atclient_monitor_response_error_read {
  int error_code; // if 0, then the connection should be disposed of immediately, as it is of no use anymore,
                  // if MBEDTLS_ERR_SSL_TIMEOUT, then a read timeout occurred,
                  // else if < 0, then an error occurred when reading from the SSL connection.
} atclient_monitor_response_error_read;

/**
 * @brief Represents a message received from the monitor connection
 *
 * @note `type` is the type of message received, it could be a notification, a data response, or an error response and
 * reading this field will tell you which data field of the union to access. Example, if type is
 * ATCLIENT_MONITOR_MESSAGE_TYPE_NOTIFICATION,t then you should access the notification field of the union
 */
typedef struct atclient_monitor_response {
  enum atclient_monitor_response_type type;
  union {
    atclient_atnotification notification; // when is_notification is true
    char *data_response;                  // message of the data response (e.g. "ok", when "data:ok" is received)
    char *error_response;                 // message of the error_response
    atclient_monitor_response_error_read error_read;
  };
} atclient_monitor_response;

typedef struct atclient_monitor_hooks {
  int (*pre_decrypt_notification)(void);
  int (*post_decrypt_notification)(int);
} atclient_monitor_hooks;

/**
 * @brief Initializes the monitor message to a default state, ready for use in other functions.
 *
 * Example:
 * atclient_monitor_response message;
 * atclient_monitor_response_init(&message);
 *
 * @param message the message to initialize, it is assumed that the memory for this struct has already been allocated
 */
void atclient_monitor_response_init(atclient_monitor_response *message);

/**
 * @brief Initializes the monitor message to a default state, ready for use in other functions.
 *
 * @param message the message to free, it is assumed that the memory for this struct has already been allocated and was
 * previous called with atclient_monitor_response_init
 */
void atclient_monitor_response_free(atclient_monitor_response *message);

/**
 * @brief Initializes the monitor connection. It is recommended that this be called before any other monitor functions.
 * It is also recommended that this is separate from the atclient connection that it is used for  crud operations and
 * exclusively used for monitoring to avoid collisions in SSL reading.
 *
 * @param monitor_conn the atclient context for the monitor connection, must be allocated by the caller before passing
 * to this function (either statically or dynamically, it is up to the caller to make this decision)
 */
void atclient_monitor_init(atclient *monitor_conn);

/**
 * @brief Frees the monitor connection and anything that any monitor functions could have allocated in the context.
 *
 * @param monitor_conn the allocated atclient context for the monitor connection
 */
void atclient_monitor_free(atclient *monitor_conn);

/**
 * @brief pkam authenticates the monitor connection
 *
 * @param monitor_conn the atclient context for the monitor connection, assumed that it is already initialized
 * @param atserver_host the atserver host to use for the pkam authentication, see atclient_find_secondary_address for
 * typical method to find this value.
 * @param atserver_port the atserver port to use for the pkam authentication, see atclient_find_secondary_address for
 * typical method to find this value.
 * @param atkeys the atkeys to use for the pkam authentication
 * @param atsign the atsign to use for the pkam authentication
 * @return int 0 on success
 */
int atclient_monitor_pkam_authenticate(atclient *monitor_conn, const char *atserver_host, const int atserver_port,
                                       const atclient_atkeys *atkeys, const char *atsign);

/**
 * @brief Set how long `atclient_monitor_read` should wait for a message before timing out
 *
 * @param monitor_conn the pkam authenticated monitor connection
 * @param timeout_ms the timeout in milliseconds
 */
void atclient_monitor_set_read_timeout(atclient *monitor_conn, const int timeout_ms);

/**
 * @brief Sends the monitor command to the atserver to start monitoring notifications, assumed that the monitor atclient
 * context is already pkam authenticated
 *
 * @param monitor_conn ctx the atclient context for the monitor connection, must be pkam_authenticated already
 * @param regex the regex to monitor for
 * @return int 0 on success, non-zero on error
 */
int atclient_monitor_start(atclient *monitor_conn, const char *regex);

/**
 * @brief Read a notification from the monitor connection into message
 * @param monitor_conn the atclient context for the monitor connection. it is assumed that this is intialized and pkam
 * authenticated. See atclient_monitor_init and atclient_monitor_pkam_authenticate
 * @param atclient the atclient context for the atclient connection, it is advised that this connection an entirely
 * separate connection from the monitor_conn to avoid colliding messages when reading. it is assumed that this is
 * initialized and pkam authenticated.
 * @param message A pointer to the initialized atclient_monitor_response. It is up to
 * the caller to allocate memory to this struct, call atclient_monitor_response_init before passing to this function,
 * then call atclient_monitor_free use. This function populates the message struct with the notification, data response,
 * or error response read from the monitor connection.
 * @param hooks the hooks to use for the monitor connection, can be NULL if no hooks are needed
 * @return 0 on success, non-zero on error
 *
 * @note Message may be a notification, a data response, or an error response, check the type field to determine which
 * data field to use
 */
int atclient_monitor_read(atclient *monitor_conn, atclient *atclient, atclient_monitor_response *message, atclient_monitor_hooks *hooks);

/**
 * @brief Check if the monitor connection is still established (client is listening for notifications, and the server
 * still has potential to send notifications to you)
 *
 * @param monitor_conn the monitor connection to check
 * @return true if connected, false if not connected or an error happened
 */
bool atclient_monitor_is_connected(atclient *monitor_conn);

#endif
