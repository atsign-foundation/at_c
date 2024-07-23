#ifndef ATCLIENT_ATNOTIFICATION_H
#define ATCLIENT_ATNOTIFICATION_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define VALUE_INITIALIZED 0b00000001

#define ATCLIENT_ATNOTIFICATION_ID_INDEX 0
#define ATCLIENT_ATNOTIFICATION_FROM_INDEX 0
#define ATCLIENT_ATNOTIFICATION_TO_INDEX 0
#define ATCLIENT_ATNOTIFICATION_KEY_INDEX 0
#define ATCLIENT_ATNOTIFICATION_VALUE_INDEX 0
#define ATCLIENT_ATNOTIFICATION_OPERATION_INDEX 0
#define ATCLIENT_ATNOTIFICATION_EPOCHMILLIS_INDEX 0
#define ATCLIENT_ATNOTIFICATION_MESSAGETYPE_INDEX 0

#define ATCLIENT_ATNOTIFICATION_ISENCRYPTED_INDEX 1
#define ATCLIENT_ATNOTIFICATION_ENCKEYNAME_INDEX 1
#define ATCLIENT_ATNOTIFICATION_ENCALGO_INDEX 1
#define ATCLIENT_ATNOTIFICATION_IVNONCE_INDEX 1
#define ATCLIENT_ATNOTIFICATION_SKEENCKEYNAME_INDEX 1
#define ATCLIENT_ATNOTIFICATION_SKEENCALGO_INDEX 1
#define ATCLIENT_ATNOTIFICATION_DECRYPTEDVALUE_INDEX 1

// initializedfields[0]
#define ATCLIENT_ATNOTIFICATION_ID_INITIALIZED (VALUE_INITIALIZED << 0)
#define ATCLIENT_ATNOTIFICATION_FROM_INITIALIZED (VALUE_INITIALIZED << 1)
#define ATCLIENT_ATNOTIFICATION_TO_INITIALIZED (VALUE_INITIALIZED << 2)
#define ATCLIENT_ATNOTIFICATION_KEY_INITIALIZED (VALUE_INITIALIZED << 3)
#define ATCLIENT_ATNOTIFICATION_VALUE_INITIALIZED (VALUE_INITIALIZED << 4)
#define ATCLIENT_ATNOTIFICATION_OPERATION_INITIALIZED (VALUE_INITIALIZED << 5)
#define ATCLIENT_ATNOTIFICATION_EPOCHMILLIS_INITIALIZED (VALUE_INITIALIZED << 6)
#define ATCLIENT_ATNOTIFICATION_MESSAGETYPE_INITIALIZED (VALUE_INITIALIZED << 7)

// initializedfields[1]
#define ATCLIENT_ATNOTIFICATION_ISENCRYPTED_INITIALIZED (VALUE_INITIALIZED << 0)
#define ATCLIENT_ATNOTIFICATION_ENCKEYNAME_INITIALIZED (VALUE_INITIALIZED << 1)
#define ATCLIENT_ATNOTIFICATION_ENCALGO_INITIALIZED (VALUE_INITIALIZED << 2)
#define ATCLIENT_ATNOTIFICATION_IVNONCE_INITIALIZED (VALUE_INITIALIZED << 3)
#define ATCLIENT_ATNOTIFICATION_SKEENCKEYNAME_INITIALIZED (VALUE_INITIALIZED << 4)
#define ATCLIENT_ATNOTIFICATION_SKEENCALGO_INITIALIZED (VALUE_INITIALIZED << 5)
#define ATCLIENT_ATNOTIFICATION_DECRYPTEDVALUE_INITIALIZED (VALUE_INITIALIZED << 6)

/**
 * @brief Represents a notification received from the monitor connection
 */
typedef struct atclient_atnotification {
  // _initalizedfields[0]
  char *id;           // holds notification id, typically a 36 + 1 null terminated string
  char *from;         // holds the from atSign (who sent the notification)
  char *to;           // holds the to atSign (who the notification is for)
  char *key;          // holds the key of the notification (e.g. "@bob:location.app@alice")
  char *value;        // holds the value that is read from the notification, this would typically be base64 encoded and
                      // encrypted, see decryptedvalue for the decrypted value
  char *operation;    // holds the operation of the notification (e.g. "update", "delete")
  size_t epochMillis; // holds the epoch time in milliseconds when the notification was sent
  char *messageType;  // holds the message type of the notification (e.g. "data", "error")

  // _initalizedfields[1]
  bool isEncrypted : 1;
  char *encKeyName;     // in metaData
  char *encAlgo;        // in metaData
  char *ivNonce;        // in metaData
  char *skeEncKeyName;  // in metaData
  char *skeEncAlgo;     // in metaData
  char *decryptedvalue; // if isEncrypted, this will be the decrypted value

  uint8_t _initializedfields[2];
} atclient_atnotification;

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
bool atclient_atnotification_is_id_initialized(const atclient_atnotification *notification);
bool atclient_atnotification_is_from_initialized(const atclient_atnotification *notification);
bool atclient_atnotification_is_to_initialized(const atclient_atnotification *notification);
bool atclient_atnotification_is_key_initialized(const atclient_atnotification *notification);
bool atclient_atnotification_is_value_initialized(const atclient_atnotification *notification);
bool atclient_atnotification_is_operation_initialized(const atclient_atnotification *notification);
bool atclient_atnotification_is_epochmillis_initialized(const atclient_atnotification *notification);
bool atclient_atnotification_is_messagetype_initialized(const atclient_atnotification *notification);
bool atclient_atnotification_is_isencrypted_initialized(const atclient_atnotification *notification);
bool atclient_atnotification_is_enckeyname_initialized(const atclient_atnotification *notification);
bool atclient_atnotification_is_encalgo_initialized(const atclient_atnotification *notification);
bool atclient_atnotification_is_ivnonce_initialized(const atclient_atnotification *notification);
bool atclient_atnotification_is_skeenckeyname_initialized(const atclient_atnotification *notification);
bool atclient_atnotification_is_skeencalgo_initialized(const atclient_atnotification *notification);
bool atclient_atnotification_is_decryptedvalue_initialized(const atclient_atnotification *notification);

// Set a field as initialized or not
void atclient_atnotification_id_set_initialized(atclient_atnotification *notification, const bool initialized);
void atclient_atnotification_from_set_initialized(atclient_atnotification *notification, const bool initialized);
void atclient_atnotification_to_set_initialized(atclient_atnotification *notification, const bool initialized);
void atclient_atnotification_key_set_initialized(atclient_atnotification *notification, const bool initialized);
void atclient_atnotification_value_set_initialized(atclient_atnotification *notification, const bool initialized);
void atclient_atnotification_operation_set_initialized(atclient_atnotification *notification, const bool initialized);
void atclient_atnotification_epochmillis_set_initialized(atclient_atnotification *notification, const bool initialized);
void atclient_atnotification_messagetype_set_initialized(atclient_atnotification *notification, const bool initialized);
void atclient_atnotification_isencrypted_set_initialized(atclient_atnotification *notification, const bool initialized);
void atclient_atnotification_enckeyname_set_initialized(atclient_atnotification *notification, const bool initialized);
void atclient_atnotification_encalgo_set_initialized(atclient_atnotification *notification, const bool initialized);
void atclient_atnotification_ivnonce_set_initialized(atclient_atnotification *notification, const bool initialized);
void atclient_atnotification_skeenckeyname_set_initialized(atclient_atnotification *notification,
                                                           const bool initialized);
void atclient_atnotification_skeencalgo_set_initialized(atclient_atnotification *notification, const bool initialized);
void atclient_atnotification_decryptedvalue_set_initialized(atclient_atnotification *notification,
                                                            const bool initialized);

// Free a field, some fields are dynamically allocated when set
void atclient_atnotification_unset_id(atclient_atnotification *notification);
void atclient_atnotification_unset_from(atclient_atnotification *notification);
void atclient_atnotification_unset_to(atclient_atnotification *notification);
void atclient_atnotification_unset_key(atclient_atnotification *notification);
void atclient_atnotification_unset_value(atclient_atnotification *notification);
void atclient_atnotification_unset_operation(atclient_atnotification *notification);
void atclient_atnotification_unset_epochmillis(atclient_atnotification *notification);
void atclient_atnotification_unset_messagetype(atclient_atnotification *notification);
void atclient_atnotification_unset_isencrypted(atclient_atnotification *notification);
void atclient_atnotification_unset_enckeyname(atclient_atnotification *notification);
void atclient_atnotification_unset_encalgo(atclient_atnotification *notification);
void atclient_atnotification_unset_ivnonce(atclient_atnotification *notification);
void atclient_atnotification_unset_skeenckeyname(atclient_atnotification *notification);
void atclient_atnotification_unset_skeencalgo(atclient_atnotification *notification);
void atclient_atnotification_unset_decryptedvalue(atclient_atnotification *notification);

// Setters for the fields, these functions check if the field is initialized before setting the value (and overwrites if
// it is)
int atclient_atnotification_set_id(atclient_atnotification *notification, const char *id, const size_t idlen);
int atclient_atnotification_set_from(atclient_atnotification *notification, const char *from, const size_t fromlen);
int atclient_atnotification_set_to(atclient_atnotification *notification, const char *to, const size_t tolen);
int atclient_atnotification_set_key(atclient_atnotification *notification, const char *key, const size_t keylen);
int atclient_atnotification_set_value(atclient_atnotification *notification, const char *value, const size_t valuelen);
int atclient_atnotification_set_operation(atclient_atnotification *notification, const char *operation,
                                          const size_t operationlen);
int atclient_atnotification_set_epochmillis(atclient_atnotification *notification, const size_t epochMillis);
int atclient_atnotification_set_messagetype(atclient_atnotification *notification, const char *messageType,
                                            const size_t messageTypelen);
int atclient_atnotification_set_isencrypted(atclient_atnotification *notification, const bool isEncrypted);
int atclient_atnotification_set_enckeyname(atclient_atnotification *notification, const char *encKeyName,
                                           const size_t encKeyNamelen);
int atclient_atnotification_set_encalgo(atclient_atnotification *notification, const char *encAlgo,
                                        const size_t encAlgolen);
int atclient_atnotification_set_ivnonce(atclient_atnotification *notification, const char *ivNonce,
                                        const size_t ivNoncelen);
int atclient_atnotification_set_skeenckeyname(atclient_atnotification *notification, const char *skeEncKeyName,
                                              const size_t skeEncKeyNamelen);
int atclient_atnotification_set_skeencalgo(atclient_atnotification *notification, const char *skeEncAlgo,
                                           const size_t skeEncAlgolen);
int atclient_atnotification_set_decryptedvalue(atclient_atnotification *notification, const char *decryptedvalue,
                                               const size_t decryptedvaluelen);

#endif // ATCLIENT_ATNOTIFICATION_H