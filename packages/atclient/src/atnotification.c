#include "atclient/atnotification.h"
#include <atlogger/atlogger.h>
#include <stdlib.h>
#include <string.h>

#define TAG "atnotification"

void atclient_atnotification_init(atclient_atnotification *notification) {
  memset(notification, 0, sizeof(atclient_atnotification));
}

void atclient_atnotification_free(atclient_atnotification *notification) {
  if (atclient_atnotification_is_id_initialized(notification)) {
    atclient_atnotification_unset_id(notification);
  }
  if (atclient_atnotification_is_from_initialized(notification)) {
    atclient_atnotification_unset_from(notification);
  }
  if (atclient_atnotification_is_to_initialized(notification)) {
    atclient_atnotification_unset_to(notification);
  }
  if (atclient_atnotification_is_key_initialized(notification)) {
    atclient_atnotification_unset_key(notification);
  }
  if (atclient_atnotification_is_value_initialized(notification)) {
    atclient_atnotification_unset_value(notification);
  }
  if (atclient_atnotification_is_operation_initialized(notification)) {
    atclient_atnotification_unset_operation(notification);
  }
  if (atclient_atnotification_is_epoch_millis_initialized(notification)) {
    atclient_atnotification_unset_epoch_millis(notification);
  }
  if (atclient_atnotification_is_message_type_initialized(notification)) {
    atclient_atnotification_unset_message_type(notification);
  }
  if (atclient_atnotification_is_is_encrypted_initialized(notification)) {
    atclient_atnotification_unset_is_encrypted(notification);
  }
  if (atclient_atnotification_is_enc_key_name_initialized(notification)) {
    atclient_atnotification_unset_enc_key_name(notification);
  }
  if (atclient_atnotification_is_enc_algo_initialized(notification)) {
    atclient_atnotification_unset_enc_algo(notification);
  }
  if (atclient_atnotification_is_iv_nonce_initialized(notification)) {
    atclient_atnotification_unset_iv_nonce(notification);
  }
  if (atclient_atnotification_is_ske_enc_key_name_initialized(notification)) {
    atclient_atnotification_unset_ske_enc_key_name(notification);
  }
  if (atclient_atnotification_is_ske_enc_algo_initialized(notification)) {
    atclient_atnotification_unset_ske_enc_algo(notification);
  }
  if (atclient_atnotification_is_decrypted_value_initialized(notification)) {
    atclient_atnotification_unset_decrypted_value(notification);
  }
}

bool atclient_atnotification_is_id_initialized(const atclient_atnotification *notification) {
  return (notification->_initialized_fields[ATCLIENT_ATNOTIFICATION_ID_INDEX] & ATCLIENT_ATNOTIFICATION_ID_INITIALIZED);
}

bool atclient_atnotification_is_from_initialized(const atclient_atnotification *notification) {
  return (notification->_initialized_fields[ATCLIENT_ATNOTIFICATION_FROM_INDEX] &
          ATCLIENT_ATNOTIFICATION_FROM_INITIALIZED);
}

bool atclient_atnotification_is_to_initialized(const atclient_atnotification *notification) {
  return (notification->_initialized_fields[ATCLIENT_ATNOTIFICATION_TO_INDEX] & ATCLIENT_ATNOTIFICATION_TO_INITIALIZED);
}

bool atclient_atnotification_is_key_initialized(const atclient_atnotification *notification) {
  return (notification->_initialized_fields[ATCLIENT_ATNOTIFICATION_KEY_INDEX] &
          ATCLIENT_ATNOTIFICATION_KEY_INITIALIZED);
}

bool atclient_atnotification_is_value_initialized(const atclient_atnotification *notification) {
  return (notification->_initialized_fields[ATCLIENT_ATNOTIFICATION_VALUE_INDEX] &
          ATCLIENT_ATNOTIFICATION_VALUE_INITIALIZED);
}

bool atclient_atnotification_is_operation_initialized(const atclient_atnotification *notification) {
  return (notification->_initialized_fields[ATCLIENT_ATNOTIFICATION_OPERATION_INDEX] &
          ATCLIENT_ATNOTIFICATION_OPERATION_INITIALIZED);
}

bool atclient_atnotification_is_epoch_millis_initialized(const atclient_atnotification *notification) {
  return (notification->_initialized_fields[ATCLIENT_ATNOTIFICATION_EPOCHMILLIS_INDEX] &
          ATCLIENT_ATNOTIFICATION_EPOCHMILLIS_INITIALIZED);
}

bool atclient_atnotification_is_message_type_initialized(const atclient_atnotification *notification) {
  return (notification->_initialized_fields[ATCLIENT_ATNOTIFICATION_MESSAGETYPE_INDEX] &
          ATCLIENT_ATNOTIFICATION_MESSAGETYPE_INITIALIZED);
}

bool atclient_atnotification_is_is_encrypted_initialized(const atclient_atnotification *notification) {
  return (notification->_initialized_fields[ATCLIENT_ATNOTIFICATION_ISENCRYPTED_INDEX] &
          ATCLIENT_ATNOTIFICATION_ISENCRYPTED_INITIALIZED);
}

bool atclient_atnotification_is_enc_key_name_initialized(const atclient_atnotification *notification) {
  return (notification->_initialized_fields[ATCLIENT_ATNOTIFICATION_ENCKEYNAME_INDEX] &
          ATCLIENT_ATNOTIFICATION_ENCKEYNAME_INITIALIZED);
}

bool atclient_atnotification_is_enc_algo_initialized(const atclient_atnotification *notification) {
  return (notification->_initialized_fields[ATCLIENT_ATNOTIFICATION_ENCALGO_INDEX] &
          ATCLIENT_ATNOTIFICATION_ENCALGO_INITIALIZED);
}

bool atclient_atnotification_is_iv_nonce_initialized(const atclient_atnotification *notification) {
  return (notification->_initialized_fields[ATCLIENT_ATNOTIFICATION_IVNONCE_INDEX] &
          ATCLIENT_ATNOTIFICATION_IVNONCE_INITIALIZED);
}

bool atclient_atnotification_is_ske_enc_key_name_initialized(const atclient_atnotification *notification) {
  return (notification->_initialized_fields[ATCLIENT_ATNOTIFICATION_SKEENCKEYNAME_INDEX] &
          ATCLIENT_ATNOTIFICATION_SKEENCKEYNAME_INITIALIZED);
}

bool atclient_atnotification_is_ske_enc_algo_initialized(const atclient_atnotification *notification) {
  return (notification->_initialized_fields[ATCLIENT_ATNOTIFICATION_SKEENCALGO_INDEX] &
          ATCLIENT_ATNOTIFICATION_SKEENCALGO_INITIALIZED);
}

bool atclient_atnotification_is_decrypted_value_initialized(const atclient_atnotification *notification) {
  return (notification->_initialized_fields[ATCLIENT_ATNOTIFICATION_DECRYPTEDVALUE_INDEX] &
          ATCLIENT_ATNOTIFICATION_DECRYPTEDVALUE_INITIALIZED);
}

void atclient_atnotification_id_set_initialized(atclient_atnotification *notification, const bool initialized) {
  if (initialized) {
    notification->_initialized_fields[ATCLIENT_ATNOTIFICATION_ID_INDEX] |= ATCLIENT_ATNOTIFICATION_ID_INITIALIZED;
  } else {
    notification->_initialized_fields[ATCLIENT_ATNOTIFICATION_ID_INDEX] &= ~ATCLIENT_ATNOTIFICATION_ID_INITIALIZED;
  }
}

void atclient_atnotification_from_set_initialized(atclient_atnotification *notification, const bool initialized) {
  if (initialized) {
    notification->_initialized_fields[ATCLIENT_ATNOTIFICATION_FROM_INDEX] |= ATCLIENT_ATNOTIFICATION_FROM_INITIALIZED;
  } else {
    notification->_initialized_fields[ATCLIENT_ATNOTIFICATION_FROM_INDEX] &= ~ATCLIENT_ATNOTIFICATION_FROM_INITIALIZED;
  }
}

void atclient_atnotification_to_set_initialized(atclient_atnotification *notification, const bool initialized) {
  if (initialized) {
    notification->_initialized_fields[ATCLIENT_ATNOTIFICATION_TO_INDEX] |= ATCLIENT_ATNOTIFICATION_TO_INITIALIZED;
  } else {
    notification->_initialized_fields[ATCLIENT_ATNOTIFICATION_TO_INDEX] &= ~ATCLIENT_ATNOTIFICATION_TO_INITIALIZED;
  }
}

void atclient_atnotification_key_set_initialized(atclient_atnotification *notification, const bool initialized) {
  if (initialized) {
    notification->_initialized_fields[ATCLIENT_ATNOTIFICATION_KEY_INDEX] |= ATCLIENT_ATNOTIFICATION_KEY_INITIALIZED;
  } else {
    notification->_initialized_fields[ATCLIENT_ATNOTIFICATION_KEY_INDEX] &= ~ATCLIENT_ATNOTIFICATION_KEY_INITIALIZED;
  }
}

void atclient_atnotification_value_set_initialized(atclient_atnotification *notification, const bool initialized) {
  if (initialized) {
    notification->_initialized_fields[ATCLIENT_ATNOTIFICATION_VALUE_INDEX] |= ATCLIENT_ATNOTIFICATION_VALUE_INITIALIZED;
  } else {
    notification->_initialized_fields[ATCLIENT_ATNOTIFICATION_VALUE_INDEX] &= ~ATCLIENT_ATNOTIFICATION_VALUE_INITIALIZED;
  }
}

void atclient_atnotification_operation_set_initialized(atclient_atnotification *notification, const bool initialized) {
  if (initialized) {
    notification->_initialized_fields[ATCLIENT_ATNOTIFICATION_OPERATION_INDEX] |=
        ATCLIENT_ATNOTIFICATION_OPERATION_INITIALIZED;
  } else {
    notification->_initialized_fields[ATCLIENT_ATNOTIFICATION_OPERATION_INDEX] &=
        ~ATCLIENT_ATNOTIFICATION_OPERATION_INITIALIZED;
  }
}

void atclient_atnotification_epoch_millis_set_initialized(atclient_atnotification *notification, const bool initialized) {
  if (initialized) {
    notification->_initialized_fields[ATCLIENT_ATNOTIFICATION_EPOCHMILLIS_INDEX] |=
        ATCLIENT_ATNOTIFICATION_EPOCHMILLIS_INITIALIZED;
  } else {
    notification->_initialized_fields[ATCLIENT_ATNOTIFICATION_EPOCHMILLIS_INDEX] &=
        ~ATCLIENT_ATNOTIFICATION_EPOCHMILLIS_INITIALIZED;
  }
}

void atclient_atnotification_message_type_set_initialized(atclient_atnotification *notification, const bool initialized) {
  if (initialized) {
    notification->_initialized_fields[ATCLIENT_ATNOTIFICATION_MESSAGETYPE_INDEX] |=
        ATCLIENT_ATNOTIFICATION_MESSAGETYPE_INITIALIZED;
  } else {
    notification->_initialized_fields[0] &= ~ATCLIENT_ATNOTIFICATION_MESSAGETYPE_INITIALIZED;
  }
}

void atclient_atnotification_is_encrypted_set_initialized(atclient_atnotification *notification, const bool initialized) {
  if (initialized) {
    notification->_initialized_fields[ATCLIENT_ATNOTIFICATION_ISENCRYPTED_INDEX] |=
        ATCLIENT_ATNOTIFICATION_ISENCRYPTED_INITIALIZED;
  } else {
    notification->_initialized_fields[ATCLIENT_ATNOTIFICATION_ISENCRYPTED_INDEX] &=
        ~ATCLIENT_ATNOTIFICATION_ISENCRYPTED_INITIALIZED;
  }
}

void atclient_atnotification_enc_key_name_set_initialized(atclient_atnotification *notification, const bool initialized) {
  if (initialized) {
    notification->_initialized_fields[ATCLIENT_ATNOTIFICATION_ENCKEYNAME_INDEX] |=
        ATCLIENT_ATNOTIFICATION_ENCKEYNAME_INITIALIZED;
  } else {
    notification->_initialized_fields[1] &= ~ATCLIENT_ATNOTIFICATION_ENCKEYNAME_INITIALIZED;
  }
}

void atclient_atnotification_enc_algo_set_initialized(atclient_atnotification *notification, const bool initialized) {
  if (initialized) {
    notification->_initialized_fields[ATCLIENT_ATNOTIFICATION_ENCALGO_INDEX] |=
        ATCLIENT_ATNOTIFICATION_ENCALGO_INITIALIZED;
  } else {
    notification->_initialized_fields[ATCLIENT_ATNOTIFICATION_ENCALGO_INDEX] &=
        ~ATCLIENT_ATNOTIFICATION_ENCALGO_INITIALIZED;
  }
}

void atclient_atnotification_iv_nonce_set_initialized(atclient_atnotification *notification, const bool initialized) {
  if (initialized) {
    notification->_initialized_fields[ATCLIENT_ATNOTIFICATION_IVNONCE_INDEX] |=
        ATCLIENT_ATNOTIFICATION_IVNONCE_INITIALIZED;
  } else {
    notification->_initialized_fields[ATCLIENT_ATNOTIFICATION_IVNONCE_INDEX] &=
        ~ATCLIENT_ATNOTIFICATION_IVNONCE_INITIALIZED;
  }
}

void atclient_atnotification_ske_enc_key_name_set_initialized(atclient_atnotification *notification, const bool initialized) {
  if (initialized) {
    notification->_initialized_fields[ATCLIENT_ATNOTIFICATION_SKEENCKEYNAME_INDEX] |=
        ATCLIENT_ATNOTIFICATION_SKEENCKEYNAME_INITIALIZED;
  } else {
    notification->_initialized_fields[ATCLIENT_ATNOTIFICATION_SKEENCKEYNAME_INDEX] &=
        ~ATCLIENT_ATNOTIFICATION_SKEENCKEYNAME_INITIALIZED;
  }
}

void atclient_atnotification_ske_enc_algo_set_initialized(atclient_atnotification *notification, const bool initialized) {
  if (initialized) {
    notification->_initialized_fields[ATCLIENT_ATNOTIFICATION_SKEENCALGO_INDEX] |=
        ATCLIENT_ATNOTIFICATION_SKEENCALGO_INITIALIZED;
  } else {
    notification->_initialized_fields[ATCLIENT_ATNOTIFICATION_SKEENCALGO_INDEX] &=
        ~ATCLIENT_ATNOTIFICATION_SKEENCALGO_INITIALIZED;
  }
}

void atclient_atnotification_decrypted_value_set_initialized(atclient_atnotification *notification, const bool initialized) {
  if (initialized) {
    notification->_initialized_fields[ATCLIENT_ATNOTIFICATION_DECRYPTEDVALUE_INDEX] |=
        ATCLIENT_ATNOTIFICATION_DECRYPTEDVALUE_INITIALIZED;
  } else {
    notification->_initialized_fields[ATCLIENT_ATNOTIFICATION_DECRYPTEDVALUE_INDEX] &=
        ~ATCLIENT_ATNOTIFICATION_DECRYPTEDVALUE_INITIALIZED;
  }
}

void atclient_atnotification_unset_id(atclient_atnotification *notification) {
  if (atclient_atnotification_is_id_initialized(notification)) {
    free(notification->id);
  }
  notification->id = NULL;
  atclient_atnotification_id_set_initialized(notification, false);
  atclient_atnotification_id_set_initialized(notification, false);
}

void atclient_atnotification_unset_from(atclient_atnotification *notification) {
  if (atclient_atnotification_is_from_initialized(notification)) {
    free(notification->from);
  }
  notification->from = NULL;
  atclient_atnotification_from_set_initialized(notification, false);
}

void atclient_atnotification_unset_to(atclient_atnotification *notification) {
  if (atclient_atnotification_is_to_initialized(notification)) {
    free(notification->to);
  }
  notification->to = NULL;
  atclient_atnotification_to_set_initialized(notification, false);
}
void atclient_atnotification_unset_key(atclient_atnotification *notification) {
  if (atclient_atnotification_is_key_initialized(notification)) {
    free(notification->key);
  }
  notification->key = NULL;
  atclient_atnotification_key_set_initialized(notification, false);
}
void atclient_atnotification_unset_value(atclient_atnotification *notification) {
  if (atclient_atnotification_is_value_initialized(notification)) {
    free(notification->value);
  }
  notification->value = NULL;
  atclient_atnotification_value_set_initialized(notification, false);
}
void atclient_atnotification_unset_operation(atclient_atnotification *notification) {
  if (atclient_atnotification_is_operation_initialized(notification)) {
    free(notification->operation);
  }
  notification->operation = NULL;
  atclient_atnotification_operation_set_initialized(notification, false);
}
void atclient_atnotification_unset_epoch_millis(atclient_atnotification *notification) {
  notification->epoch_millis = 0;
  atclient_atnotification_epoch_millis_set_initialized(notification, false);
}

void atclient_atnotification_unset_message_type(atclient_atnotification *notification) {
  if (atclient_atnotification_is_message_type_initialized(notification)) {
    free(notification->message_type);
  }
  notification->message_type = NULL;
  atclient_atnotification_message_type_set_initialized(notification, false);
}

void atclient_atnotification_unset_is_encrypted(atclient_atnotification *notification) {
  notification->is_encrypted = false;
  atclient_atnotification_is_encrypted_set_initialized(notification, false);
}

void atclient_atnotification_unset_enc_key_name(atclient_atnotification *notification) {
  if (atclient_atnotification_is_enc_key_name_initialized(notification)) {
    free(notification->enc_key_name);
  }
  notification->enc_key_name = NULL;
  atclient_atnotification_enc_key_name_set_initialized(notification, false);
}

void atclient_atnotification_unset_enc_algo(atclient_atnotification *notification) {
  if (atclient_atnotification_is_enc_algo_initialized(notification)) {
    free(notification->enc_algo);
  }
  notification->enc_algo = NULL;
  atclient_atnotification_enc_algo_set_initialized(notification, false);
}

void atclient_atnotification_unset_iv_nonce(atclient_atnotification *notification) {
  if (atclient_atnotification_is_iv_nonce_initialized(notification)) {
    free(notification->iv_nonce);
  }
  notification->iv_nonce = NULL;
  atclient_atnotification_iv_nonce_set_initialized(notification, false);
}

void atclient_atnotification_unset_ske_enc_key_name(atclient_atnotification *notification) {
  if (atclient_atnotification_is_ske_enc_key_name_initialized(notification)) {
    free(notification->ske_enc_key_name);
  }
  notification->ske_enc_key_name = NULL;
  atclient_atnotification_ske_enc_key_name_set_initialized(notification, false);
}

void atclient_atnotification_unset_ske_enc_algo(atclient_atnotification *notification) {
  if (atclient_atnotification_is_ske_enc_algo_initialized(notification)) {
    free(notification->ske_enc_algo);
  }
  notification->ske_enc_algo = NULL;
  atclient_atnotification_ske_enc_algo_set_initialized(notification, false);
}

void atclient_atnotification_unset_decrypted_value(atclient_atnotification *notification) {
  if (atclient_atnotification_is_decrypted_value_initialized(notification)) {
    free(notification->decrypted_value);
  }
  notification->decrypted_value = NULL;
  atclient_atnotification_decrypted_value_set_initialized(notification, false);
}

int atclient_atnotification_set_id(atclient_atnotification *notification, const char *id) {
  int ret = 1;
  if (atclient_atnotification_is_id_initialized(notification)) {
    atclient_atnotification_unset_id(notification);
  }
  const size_t id_len = strlen(id);
  const size_t id_size = id_len + 1;
  if ((notification->id = malloc(sizeof(char) * id_size)) == NULL) {
    ret = 1;
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "Failed to allocate memory for notification id\n");
    goto exit;
  }
  memcpy(notification->id, id, id_len);
  *(notification->id + id_len) = '\0';
  atclient_atnotification_id_set_initialized(notification, true);
  ret = 0;
  goto exit;
exit: { return ret; }
}

int atclient_atnotification_set_from(atclient_atnotification *notification, const char *from) {
  int ret = 1;
  if (atclient_atnotification_is_from_initialized(notification)) {
    atclient_atnotification_unset_from(notification);
  }
  const size_t from_len = strlen(from);
  const size_t from_size = from_len + 1;
  if ((notification->from = malloc(sizeof(char) * from_size)) == NULL) {
    ret = 1;
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "Failed to allocate memory for notification from\n");
    goto exit;
  }
  memcpy(notification->from, from, from_len);
  *(notification->from + from_len) = '\0';
  atclient_atnotification_from_set_initialized(notification, true);
  ret = 0;
  goto exit;
exit: { return ret; }
}

int atclient_atnotification_set_to(atclient_atnotification *notification, const char *to) {
  int ret = 1;
  if (atclient_atnotification_is_to_initialized(notification)) {
    atclient_atnotification_unset_to(notification);
  }
  const size_t to_len = strlen(to);
  const size_t to_size = to_len + 1;
  if ((notification->to = malloc(sizeof(char) * to_size)) == NULL) {
    ret = 1;
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "Failed to allocate memory for notification to\n");
    goto exit;
  }
  memcpy(notification->to, to, to_len);
  *(notification->to + to_len) = '\0';
  atclient_atnotification_to_set_initialized(notification, true);
  ret = 0;
  goto exit;
exit: { return ret; }
}

int atclient_atnotification_set_key(atclient_atnotification *notification, const char *key) {
  int ret = 1;
  if (atclient_atnotification_is_key_initialized(notification)) {
    atclient_atnotification_unset_key(notification);
  }
  const size_t key_len = strlen(key);
  const size_t key_size = key_len + 1;
  if ((notification->key = malloc(sizeof(char) * key_size)) == NULL) {
    ret = 1;
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "Failed to allocate memory for notification key\n");
    goto exit;
  }
  memcpy(notification->key, key, key_len);
  *(notification->key + key_len) = '\0';
  atclient_atnotification_key_set_initialized(notification, true);
  ret = 0;
  goto exit;
exit: { return ret; }
}

int atclient_atnotification_set_value(atclient_atnotification *notification, const char *value) {
  int ret = 1;
  if (atclient_atnotification_is_value_initialized(notification)) {
    atclient_atnotification_unset_value(notification);
  }
  const size_t value_len = strlen(value);
  const size_t value_size = value_len + 1;
  if ((notification->value = malloc(sizeof(char) * value_size)) == NULL) {
    ret = 1;
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "Failed to allocate memory for notification value\n");
    goto exit;
  }
  memcpy(notification->value, value, value_len);
  *(notification->value + value_len) = '\0';
  atclient_atnotification_value_set_initialized(notification, true);
  ret = 0;
  goto exit;
exit: { return ret; }
}

int atclient_atnotification_set_operation(atclient_atnotification *notification, const char *operation) {
  int ret = 1;
  if (atclient_atnotification_is_operation_initialized(notification)) {
    atclient_atnotification_unset_operation(notification);
  }
  const size_t operation_len = strlen(operation);
  const size_t operation_size = operation_len + 1;
  if ((notification->operation = malloc(sizeof(char) * operation_size)) == NULL) {
    ret = 1;
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "Failed to allocate memory for notification operation\n");
    goto exit;
  }
  memcpy(notification->operation, operation, operation_len);
  *(notification->operation + operation_len) = '\0';
  atclient_atnotification_operation_set_initialized(notification, true);
  ret = 0;
  goto exit;
exit: { return ret; }
}

int atclient_atnotification_set_epoch_millis(atclient_atnotification *notification, const size_t epoch_millis) {
  if (atclient_atnotification_is_epoch_millis_initialized(notification)) {
    atclient_atnotification_unset_epoch_millis(notification);
  }
  notification->epoch_millis = epoch_millis;
  atclient_atnotification_epoch_millis_set_initialized(notification, true);
  return 0;
}

int atclient_atnotification_set_message_type(atclient_atnotification *notification, const char *message_type) {
  int ret = 1;
  if (atclient_atnotification_is_message_type_initialized(notification)) {
    atclient_atnotification_unset_message_type(notification);
  }
  const size_t message_type_len = strlen(message_type);
  const size_t message_type_size = message_type_len + 1;
  if ((notification->message_type = malloc(sizeof(char) * message_type_size)) == NULL) {
    ret = 1;
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "Failed to allocate memory for notification message_type\n");
    goto exit;
  }
  memcpy(notification->message_type, message_type, message_type_len);
  *(notification->message_type + message_type_len) = '\0';
  atclient_atnotification_message_type_set_initialized(notification, true);
  ret = 0;
  goto exit;
exit: { return ret; }
}

int atclient_atnotification_set_is_encrypted(atclient_atnotification *notification, const bool is_encrypted) {
  if (atclient_atnotification_is_is_encrypted_initialized(notification)) {
    atclient_atnotification_unset_is_encrypted(notification);
  }
  notification->is_encrypted = is_encrypted;
  atclient_atnotification_is_encrypted_set_initialized(notification, true);
  return 0;
}

int atclient_atnotification_set_enc_key_name(atclient_atnotification *notification, const char *enc_key_name) {
  int ret = 1;
  if (atclient_atnotification_is_enc_key_name_initialized(notification)) {
    atclient_atnotification_unset_enc_key_name(notification);
  }
  const size_t enc_key_name_len = strlen(enc_key_name);
  const size_t enc_key_name_size = enc_key_name_len + 1;
  if ((notification->enc_key_name = malloc(sizeof(char) * enc_key_name_size)) == NULL) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "Failed to allocate memory for notification enc_key_name\n");
    goto exit;
  }
  memcpy(notification->enc_key_name, enc_key_name, enc_key_name_len);
  *(notification->enc_key_name + enc_key_name_len) = '\0';
  atclient_atnotification_enc_key_name_set_initialized(notification, true);
  ret = 0;
  goto exit;
exit: { return ret; }
}

int atclient_atnotification_set_enc_algo(atclient_atnotification *notification, const char *enc_algo) {
  int ret = 1;
  if (atclient_atnotification_is_enc_algo_initialized(notification)) {
    atclient_atnotification_unset_enc_algo(notification);
  }
  const size_t enc_algo_len = strlen(enc_algo);
  const size_t enc_algo_size = enc_algo_len + 1;
  if((notification->enc_algo = malloc(sizeof(char) * enc_algo_size)) == NULL) {
    ret = 1;
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "Failed to allocate memory for notification enc_algo\n");
    goto exit;
  }
  memcpy(notification->enc_algo, enc_algo, enc_algo_len);
  *(notification->enc_algo + enc_algo_len) = '\0';
  atclient_atnotification_enc_algo_set_initialized(notification, true);
  ret = 0;
  goto exit;
exit: { return ret; }
}

int atclient_atnotification_set_iv_nonce(atclient_atnotification *notification, const char *iv_nonce) {
  int ret = 1;
  if (atclient_atnotification_is_iv_nonce_initialized(notification)) {
    atclient_atnotification_unset_iv_nonce(notification);
  }
  const size_t iv_nonce_size = strlen(iv_nonce);
  const size_t iv_nonce_len = iv_nonce_size + 1;
  if ((notification->iv_nonce = malloc(sizeof(char) * iv_nonce_size)) == NULL) {
    ret = 1;
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "Failed to allocate memory for notification iv_nonce\n");
    goto exit;
  }
  memcpy(notification->iv_nonce, iv_nonce, iv_nonce_len);
  *(notification->iv_nonce + iv_nonce_len) = '\0';
  atclient_atnotification_iv_nonce_set_initialized(notification, true);
  ret = 0;
  goto exit;
exit: { return ret; }
}

int atclient_atnotification_set_ske_enc_key_name(atclient_atnotification *notification, const char *ske_enc_key_name) {
  int ret = 1;
  if (atclient_atnotification_is_ske_enc_key_name_initialized(notification)) {
    atclient_atnotification_unset_ske_enc_key_name(notification);
  }
  const size_t ske_enc_key_name_len = strlen(ske_enc_key_name);
  const size_t ske_enc_key_name_size = ske_enc_key_name_len + 1;
  if ((notification->ske_enc_key_name = malloc(sizeof(char) * (ske_enc_key_name_size))) == NULL) {
    ret = 1;
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "Failed to allocate memory for notification ske_enc_key_name\n");
    goto exit;
  }
  memcpy(notification->ske_enc_key_name, ske_enc_key_name, ske_enc_key_name_len);
  *(notification->ske_enc_key_name + ske_enc_key_name_len) = '\0';
  atclient_atnotification_ske_enc_key_name_set_initialized(notification, true);
  ret = 0;
  goto exit;
exit: { return ret; }
}

int atclient_atnotification_set_ske_enc_algo(atclient_atnotification *notification, const char *ske_enc_algo) {
  int ret = 1;
  if (atclient_atnotification_is_ske_enc_algo_initialized(notification)) {
    atclient_atnotification_unset_ske_enc_algo(notification);
  }
  const size_t ske_enc_algo_len = strlen(ske_enc_algo);
  const size_t ske_enc_algo_size = ske_enc_algo_len + 1;
  if ((notification->ske_enc_algo = malloc(sizeof(char) * ske_enc_algo_size)) == NULL) {
    ret = 1;
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "Failed to allocate memory for notification ske_enc_algo\n");
    goto exit;
  }
  memcpy(notification->ske_enc_algo, ske_enc_algo, ske_enc_algo_len);
  *(notification->ske_enc_algo + ske_enc_algo_len) = '\0';
  atclient_atnotification_ske_enc_algo_set_initialized(notification, true);
  ret = 0;
  goto exit;
exit: { return ret; }
}

int atclient_atnotification_set_decrypted_value(atclient_atnotification *notification, const char *decrypted_value) {
  int ret = 1;
  if (atclient_atnotification_is_decrypted_value_initialized(notification)) {
    atclient_atnotification_unset_decrypted_value(notification);
  }
  const size_t decrypted_value_len = strlen(decrypted_value);
  const size_t decrypted_value_size = decrypted_value_len + 1;
  if ((notification->decrypted_value = malloc(sizeof(unsigned char) * decrypted_value_size)) == NULL) {
    ret = 1;
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "Failed to allocate memory for notification decrypted_value\n");
    goto exit;
  }
  memcpy(notification->decrypted_value, decrypted_value, decrypted_value_len);
  notification->decrypted_value[decrypted_value_len] = '\0';
  atclient_atnotification_decrypted_value_set_initialized(notification, true);
  ret = 0;
  goto exit;
exit: { return ret; }
}
