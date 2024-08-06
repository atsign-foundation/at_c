#ifndef ATCLIENT_ATNOTIFICATION_H
#define ATCLIENT_ATNOTIFICATION_H

#include "atclient/cjson.h"
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
                      // encrypted, see decrypted_value for the decrypted value
  char *operation;    // holds the operation of the notification (e.g. "update", "delete")
  size_t epoch_millis; // holds the epoch time in milliseconds when the notification was sent
  char *message_type;  // holds the message type of the notification (e.g. "data", "error")

  // _initalizedfields[1]
  bool is_encrypted : 1;
  char *enc_key_name;     // in metaData
  char *enc_algo;        // in metaData
  char *iv_nonce;        // in metaData
  char *ske_enc_key_name;  // in metaData
  char *ske_enc_algo;     // in metaData
  char *decrypted_value; // if is_encrypted, this will be the decrypted value

  uint8_t _initialized_fields[2];
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

int atclient_atnotification_from_json_str(atclient_atnotification *notification, const char *json_str);
int atclient_atnotification_from_cjson_node(atclient_atnotification *notification, const cJSON *root);

// Check if a field is initialized
bool atclient_atnotification_is_id_initialized(const atclient_atnotification *notification);
bool atclient_atnotification_is_from_initialized(const atclient_atnotification *notification);
bool atclient_atnotification_is_to_initialized(const atclient_atnotification *notification);
bool atclient_atnotification_is_key_initialized(const atclient_atnotification *notification);
bool atclient_atnotification_is_value_initialized(const atclient_atnotification *notification);
bool atclient_atnotification_is_operation_initialized(const atclient_atnotification *notification);
bool atclient_atnotification_is_epoch_millis_initialized(const atclient_atnotification *notification);
bool atclient_atnotification_is_message_type_initialized(const atclient_atnotification *notification);
bool atclient_atnotification_is_is_encrypted_initialized(const atclient_atnotification *notification);
bool atclient_atnotification_is_enc_key_name_initialized(const atclient_atnotification *notification);
bool atclient_atnotification_is_enc_algo_initialized(const atclient_atnotification *notification);
bool atclient_atnotification_is_iv_nonce_initialized(const atclient_atnotification *notification);
bool atclient_atnotification_is_ske_enc_key_name_initialized(const atclient_atnotification *notification);
bool atclient_atnotification_is_ske_enc_algo_initialized(const atclient_atnotification *notification);
bool atclient_atnotification_is_decrypted_value_initialized(const atclient_atnotification *notification);

// Free a field, some fields are dynamically allocated when set
void atclient_atnotification_unset_id(atclient_atnotification *notification);
void atclient_atnotification_unset_from(atclient_atnotification *notification);
void atclient_atnotification_unset_to(atclient_atnotification *notification);
void atclient_atnotification_unset_key(atclient_atnotification *notification);
void atclient_atnotification_unset_value(atclient_atnotification *notification);
void atclient_atnotification_unset_operation(atclient_atnotification *notification);
void atclient_atnotification_unset_epoch_millis(atclient_atnotification *notification);
void atclient_atnotification_unset_message_type(atclient_atnotification *notification);
void atclient_atnotification_unset_is_encrypted(atclient_atnotification *notification);
void atclient_atnotification_unset_enc_key_name(atclient_atnotification *notification);
void atclient_atnotification_unset_enc_algo(atclient_atnotification *notification);
void atclient_atnotification_unset_iv_nonce(atclient_atnotification *notification);
void atclient_atnotification_unset_ske_enc_key_name(atclient_atnotification *notification);
void atclient_atnotification_unset_ske_enc_algo(atclient_atnotification *notification);
void atclient_atnotification_unset_decrypted_value(atclient_atnotification *notification);

// Setters for the fields, these functions check if the field is initialized before setting the value (and overwrites if
// it is)
int atclient_atnotification_set_id(atclient_atnotification *notification, const char *id);
int atclient_atnotification_set_from(atclient_atnotification *notification, const char *from);
int atclient_atnotification_set_to(atclient_atnotification *notification, const char *to);
int atclient_atnotification_set_key(atclient_atnotification *notification, const char *key);
int atclient_atnotification_set_value(atclient_atnotification *notification, const char *value);
int atclient_atnotification_set_operation(atclient_atnotification *notification, const char *operation);
int atclient_atnotification_set_epoch_millis(atclient_atnotification *notification, const size_t epoch_millis);
int atclient_atnotification_set_message_type(atclient_atnotification *notification, const char *message_type);
int atclient_atnotification_set_is_encrypted(atclient_atnotification *notification, const bool is_encrypted);
int atclient_atnotification_set_enc_key_name(atclient_atnotification *notification, const char *enc_key_name);
int atclient_atnotification_set_enc_algo(atclient_atnotification *notification, const char *enc_algo);
int atclient_atnotification_set_iv_nonce(atclient_atnotification *notification, const char *iv_nonce);
int atclient_atnotification_set_ske_enc_key_name(atclient_atnotification *notification, const char *ske_enc_key_name);
int atclient_atnotification_set_ske_enc_algo(atclient_atnotification *notification, const char *ske_enc_algo);
int atclient_atnotification_set_decrypted_value(atclient_atnotification *notification, const char *decrypted_value);

#endif // ATCLIENT_ATNOTIFICATION_H