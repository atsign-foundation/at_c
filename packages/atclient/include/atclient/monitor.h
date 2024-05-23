#ifndef NOTIFICATION_H
#define NOTIFICATION_H

#include "atclient.h"
#include "atkey.h"

/**
 * @brief Represents a notification received from the monitor connection
 */
typedef struct atclient_atnotification {
  // initializedfields[0]
  char *id;           // holds notification id, typically a 36 + 1 null terminated string
  char *from;         // holds the from atSign (who sent the notification)
  char *to;           // holds the to atSign (who the notification is for)
  char *key;          // holds the key of the notification (e.g. "@bob:location.app@alice")
  char *value;        // holds the value that is read from the notification, this would typically be base64 encoded and
                      // encrypted, see decryptedvalue for the decrypted value
  char *operation;    // holds the operation of the notification (e.g. "update", "delete")
  size_t epochMillis; // holds the epoch time in milliseconds when the notification was sent
  char *messageType;  // holds the message type of the notification (e.g. "data", "error")

  // initalizedfields[1]
  bool isEncrypted : 1;
  char *encKeyName;              // in metaData
  char *encAlgo;                 // in metaData
  char *ivNonce;                 // in metaData
  char *skeEncKeyName;           // in metaData
  char *skeEncAlgo;              // in metaData
  unsigned char *decryptedvalue; // if isEncrypted, this will be the decrypted value
  size_t decryptedvaluelen;      // represents the length of the decrypted value

  uint8_t initalizedfields[2];
} atclient_atnotification;

#define ATCLIENT_ATNOTIFICATION_INITIALIZED 0b00000001

// initializedfields[0]
#define ATCLIENT_ATNOTIFICATION_ID_INITIALIZED (ATCLIENT_ATNOTIFICATION_INITIALIZED << 0)
#define ATCLIENT_ATNOTIFICATION_FROM_INITIALIZED (ATCLIENT_ATNOTIFICATION_INITIALIZED << 1)
#define ATCLIENT_ATNOTIFICATION_TO_INITIALIZED (ATCLIENT_ATNOTIFICATION_INITIALIZED << 2)
#define ATCLIENT_ATNOTIFICATION_KEY_INITIALIZED (ATCLIENT_ATNOTIFICATION_INITIALIZED << 3)
#define ATCLIENT_ATNOTIFICATION_VALUE_INITIALIZED (ATCLIENT_ATNOTIFICATION_INITIALIZED << 4)
#define ATCLIENT_ATNOTIFICATION_OPERATION_INITIALIZED (ATCLIENT_ATNOTIFICATION_INITIALIZED << 5)
#define ATCLIENT_ATNOTIFICATION_EPOCHMILLIS_INITIALIZED (ATCLIENT_ATNOTIFICATION_INITIALIZED << 6)
#define ATCLIENT_ATNOTIFICATION_MESSAGETYPE_INITIALIZED (ATCLIENT_ATNOTIFICATION_INITIALIZED << 7)

// initializedfields[1]
#define ATCLIENT_ATNOTIFICATION_ISENCRYPTED_INITIALIZED (ATCLIENT_ATNOTIFICATION_INITIALIZED << 0)
#define ATCLIENT_ATNOTIFICATION_ENCKEYNAME_INITIALIZED (ATCLIENT_ATNOTIFICATION_INITIALIZED << 1)
#define ATCLIENT_ATNOTIFICATION_ENCALGO_INITIALIZED (ATCLIENT_ATNOTIFICATION_INITIALIZED << 2)
#define ATCLIENT_ATNOTIFICATION_IVNONCE_INITIALIZED (ATCLIENT_ATNOTIFICATION_INITIALIZED << 3)
#define ATCLIENT_ATNOTIFICATION_SKEENCKEYNAME_INITIALIZED (ATCLIENT_ATNOTIFICATION_INITIALIZED << 4)
#define ATCLIENT_ATNOTIFICATION_SKEENCALGO_INITIALIZED (ATCLIENT_ATNOTIFICATION_INITIALIZED << 5)
#define ATCLIENT_ATNOTIFICATION_DECRYPTEDVALUE_INITIALIZED (ATCLIENT_ATNOTIFICATION_INITIALIZED << 6)
#define ATCLIENT_ATNOTIFICATION_DECRYPTEDVALUELEN_INITIALIZED (ATCLIENT_ATNOTIFICATION_INITIALIZED << 7)

/**
 * @brief Initializes the atnotification to a default state, ready for use in other functions.
 *
 * Example use:
 * atclient_atnotification notification;
 * atclient_atnotification_init(&notification);
 *
 * @param notification pointer to the atnotification to initialize, it is assumed that the memory for this struct has
 * already been allocated (either statically or dynamically, it is up to the caller to make this decision)
 */
void atclient_atnotification_init(atclient_atnotification *notification);

/**
 * @brief Frees the memory allocated for the atnotification. _init or any subsequent functions may have allocated memory
 * in this context and it is the caller's responsibility to free this memory.
 *
 * @param notification the atnotification to free, assumed to already have been allocated by the caller and initialized
 * by the caller using _init
 */
void atclient_atnotification_free(atclient_atnotification *notification);

// Check if a field is initialized
bool atclient_atnotification_id_is_initialized(const atclient_atnotification *notification);
bool atclient_atnotification_from_is_initialized(const atclient_atnotification *notification);
bool atclient_atnotification_to_is_initialized(const atclient_atnotification *notification);
bool atclient_atnotification_key_is_initialized(const atclient_atnotification *notification);
bool atclient_atnotification_value_is_initialized(const atclient_atnotification *notification);
bool atclient_atnotification_operation_is_initialized(const atclient_atnotification *notification);
bool atclient_atnotification_epochMillis_is_initialized(const atclient_atnotification *notification);
bool atclient_atnotification_messageType_is_initialized(const atclient_atnotification *notification);
bool atclient_atnotification_isEncrypted_is_initialized(const atclient_atnotification *notification);
bool atclient_atnotification_encKeyName_is_initialized(const atclient_atnotification *notification);
bool atclient_atnotification_encAlgo_is_initialized(const atclient_atnotification *notification);
bool atclient_atnotification_ivNonce_is_initialized(const atclient_atnotification *notification);
bool atclient_atnotification_skeEncKeyName_is_initialized(const atclient_atnotification *notification);
bool atclient_atnotification_skeEncAlgo_is_initialized(const atclient_atnotification *notification);
bool atclient_atnotification_decryptedvalue_is_initialized(const atclient_atnotification *notification);
bool atclient_atnotification_decryptedvaluelen_is_initialized(const atclient_atnotification *notification);

// Set a field as initialized or not
void atclient_atnotification_id_set_initialized(atclient_atnotification *notification, bool initialized);
void atclient_atnotification_from_set_initialized(atclient_atnotification *notification, bool initialized);
void atclient_atnotification_to_set_initialized(atclient_atnotification *notification, bool initialized);
void atclient_atnotification_key_set_initialized(atclient_atnotification *notification, bool initialized);
void atclient_atnotification_value_set_initialized(atclient_atnotification *notification, bool initialized);
void atclient_atnotification_operation_set_initialized(atclient_atnotification *notification, bool initialized);
void atclient_atnotification_epochMillis_set_initialized(atclient_atnotification *notification, bool initialized);
void atclient_atnotification_messageType_set_initialized(atclient_atnotification *notification, bool initialized);
void atclient_atnotification_isEncrypted_set_initialized(atclient_atnotification *notification, bool initialized);
void atclient_atnotification_encKeyName_set_initialized(atclient_atnotification *notification, bool initialized);
void atclient_atnotification_encAlgo_set_initialized(atclient_atnotification *notification, bool initialized);
void atclient_atnotification_ivNonce_set_initialized(atclient_atnotification *notification, bool initialized);
void atclient_atnotification_skeEncKeyName_set_initialized(atclient_atnotification *notification, bool initialized);
void atclient_atnotification_skeEncAlgo_set_initialized(atclient_atnotification *notification, bool initialized);
void atclient_atnotification_decryptedvalue_set_initialized(atclient_atnotification *notification, bool initialized);
void atclient_atnotification_decryptedvaluelen_set_initialized(atclient_atnotification *notification, bool initialized);

// Free a field, some fields are dynamically allocated when set
void atclient_atnotification_free_id(atclient_atnotification *notification);
void atclient_atnotification_free_from(atclient_atnotification *notification);
void atclient_atnotification_free_to(atclient_atnotification *notification);
void atclient_atnotification_free_key(atclient_atnotification *notification);
void atclient_atnotification_free_value(atclient_atnotification *notification);
void atclient_atnotification_free_operation(atclient_atnotification *notification);
void atclient_atnotification_free_epochMillis(atclient_atnotification *notification);
void atclient_atnotification_free_messageType(atclient_atnotification *notification);
void atclient_atnotification_free_isEncrypted(atclient_atnotification *notification);
void atclient_atnotification_free_encKeyName(atclient_atnotification *notification);
void atclient_atnotification_free_encAlgo(atclient_atnotification *notification);
void atclient_atnotification_free_ivNonce(atclient_atnotification *notification);
void atclient_atnotification_free_skeEncKeyName(atclient_atnotification *notification);
void atclient_atnotification_free_skeEncAlgo(atclient_atnotification *notification);
void atclient_atnotification_free_decryptedvalue(atclient_atnotification *notification);
void atclient_atnotification_free_decryptedvaluelen(atclient_atnotification *notification);

// Setters for the fields, these functions check if the field is initialized before setting the value (and overwrites if
// it is)
void atclient_atnotification_set_id(atclient_atnotification *notification, const char *id, const size_t idlen);
void atclient_atnotification_set_from(atclient_atnotification *notification, const char *from, const size_t fromlen);
void atclient_atnotification_set_to(atclient_atnotification *notification, const char *to, const size_t tolen);
void atclient_atnotification_set_key(atclient_atnotification *notification, const char *key, const size_t keylen);
void atclient_atnotification_set_value(atclient_atnotification *notification, const char *value, const size_t valuelen);
void atclient_atnotification_set_operation(atclient_atnotification *notification, const char *operation,
                                           const size_t operationlen);
void atclient_atnotification_set_epochMillis(atclient_atnotification *notification, const size_t epochMillis);
void atclient_atnotification_set_messageType(atclient_atnotification *notification, const char *messageType,
                                             const size_t messageTypelen);
void atclient_atnotification_set_isEncrypted(atclient_atnotification *notification, const bool isEncrypted);
void atclient_atnotification_set_encKeyName(atclient_atnotification *notification, const char *encKeyName,
                                            const size_t encKeyNamelen);
void atclient_atnotification_set_encAlgo(atclient_atnotification *notification, const char *encAlgo,
                                         const size_t encAlgolen);
void atclient_atnotification_set_ivNonce(atclient_atnotification *notification, const char *ivNonce,
                                         const size_t ivNoncelen);
void atclient_atnotification_set_skeEncKeyName(atclient_atnotification *notification, const char *skeEncKeyName,
                                               const size_t skeEncKeyNamelen);
void atclient_atnotification_set_skeEncAlgo(atclient_atnotification *notification, const char *skeEncAlgo,
                                            const size_t skeEncAlgolen);
void atclient_atnotification_set_decryptedvalue(atclient_atnotification *notification,
                                                const unsigned char *decryptedvalue, const size_t decryptedvaluelen);
void atclient_atnotification_set_decryptedvaluelen(atclient_atnotification *notification,
                                                   const size_t decryptedvaluelen);

/**
 * @brief Represents a message received from the monitor connection, typically derived from the prefix of the response
 * (e.g. "data:ok"'s message type would be "data" = ATCLIENT_MONITOR_MESSAGE_TYPE_DATA_RESPONSE)
 *
 */
enum atclient_monitor_message_type {
  ATCLIENT_MONITOR_MESSAGE_TYPE_NONE,
  ATCLIENT_MONITOR_MESSAGE_TYPE_NOTIFICATION,
  ATCLIENT_MONITOR_MESSAGE_TYPE_DATA_RESPONSE,
  ATCLIENT_MONITOR_MESSAGE_TYPE_ERROR_RESPONSE,
  ATCLIENT_MONITOR_ERROR_READ, // usually a socket error
  ATCLIENT_MONITOR_ERROR_PARSE,
};

/**
 * @brief Represents a message received from the monitor connection
 *
 * @note `type` is the type of message received, it could be a notification, a data response, or an error response and
 * reading this field will tell you which data field of the union to access. Example, if type is
 * ATCLIENT_MONITOR_MESSAGE_TYPE_NOTIFICATION,t then you should access the notification field of the union
 */
typedef struct atclient_monitor_message {
  enum atclient_monitor_message_type type;
  union {
    atclient_atnotification notification; // when is_notification is true
    char *data_response;                  // message of the data response (e.g. "ok", when "data:ok" is received)
    char *error_response;                 // message of the error_response
  };
} atclient_monitor_message;

/**
 * @brief Initializes the monitor message to a default state, ready for use in other functions.
 *
 * Example:
 * atclient_monitor_message message;
 * atclient_monitor_message_init(&message);
 *
 * @param message the message to initialize, it is assumed that the memory for this struct has already been allocated
 */
void atclient_monitor_message_init(atclient_monitor_message *message);

/**
 * @brief Initializes the monitor message to a default state, ready for use in other functions.
 *
 * @param message the message to free, it is assumed that the memory for this struct has already been allocated and was
 * previous called with atclient_monitor_message_init
 */
void atclient_monitor_message_free(atclient_monitor_message *message);

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
 * @param root_conn the atDirectory root connection, assumed that it is already initialized and connected to the root
 * server
 * @param atkeys the atkeys to use for the pkam authentication
 * @param atsign the atsign to use for the pkam authentication
 * @return int 0 on success
 */
int atclient_monitor_pkam_authenticate(atclient *monitor_conn, atclient_connection *root_conn,
                                       const atclient_atkeys *atkeys, const char *atsign);

/**
 * @brief Set how long `atclient_monitor_read` should wait for a message before timing out
 *
 * @param monitor_conn the pkam authenticated monitor connection
 * @param timeoutms the timeout in milliseconds
 */
void atclient_monitor_set_read_timeout(atclient *monitor_conn, const int timeoutms);

/**
 * @brief Onboards the monitor_connection and starts the monitoring connection.
 *
 * @param monitor_conn ctx the atclient context for the monitor connection, must be pkam_authenticated already
 * @param regex the regex to monitor for
 * @param regexlen the length of the regex string, most people will typically use strlen(regex)
 * @return int 0 on success
 */
int atclient_monitor_start(atclient *monitor_conn, const char *regex, const size_t regexlen);

/**
 * @brief Read a notification from the monitor connection into message
 * @param monitor_conn the atclient context for the monitor connection. it is assumed that this is intialized and pkam
 * authenticated.
 * @param atclient the atclient context for the atclient connection, it is advised that this connection an entirely
 * separate connection from the monitor_conn to avoid colliding messages when reading. it is assumed that this is
 * initialized and pkam authenticated.
 * @param message pass in a double pointer to the message, it will be allocated and filled in by this function. The
 * caller is responsible for freeing the message, using atclient_monitor_message_free
 * @return 0 on success, non-zero on error
 *
 * @note Message may be a notification, a data response, or an error response, check the type field to determine which
 * data field to use
 */
int atclient_monitor_read(atclient *monitor_conn, atclient *atclient, atclient_monitor_message **message);

/**
 * @brief Check if the monitor connection is still established (client is listening for notifications, and the server
 * still has potential to send notifications to you)
 *
 * @param monitor_conn the monitor connection to check
 * @return 1 if connected, 0 if not connected, negative on error, you can deduce that 0 and negative basically mean the
 * same thing (we are not connected :( )
 */
int atclient_monitor_is_connected(atclient *monitor_conn);

#endif
