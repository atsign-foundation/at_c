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
  if (atclient_atnotification_is_epochmillis_initialized(notification)) {
    atclient_atnotification_unset_epochmillis(notification);
  }
  if (atclient_atnotification_is_messagetype_initialized(notification)) {
    atclient_atnotification_unset_messagetype(notification);
  }
  if (atclient_atnotification_is_isencrypted_initialized(notification)) {
    atclient_atnotification_unset_isencrypted(notification);
  }
  if (atclient_atnotification_is_enckeyname_initialized(notification)) {
    atclient_atnotification_unset_enckeyname(notification);
  }
  if (atclient_atnotification_is_encalgo_initialized(notification)) {
    atclient_atnotification_unset_encalgo(notification);
  }
  if (atclient_atnotification_is_ivnonce_initialized(notification)) {
    atclient_atnotification_unset_ivnonce(notification);
  }
  if (atclient_atnotification_is_skeenckeyname_initialized(notification)) {
    atclient_atnotification_unset_skeenckeyname(notification);
  }
  if (atclient_atnotification_is_skeencalgo_initialized(notification)) {
    atclient_atnotification_unset_skeencalgo(notification);
  }
  if (atclient_atnotification_is_decryptedvalue_initialized(notification)) {
    atclient_atnotification_unset_decryptedvalue(notification);
  }
}

bool atclient_atnotification_is_id_initialized(const atclient_atnotification *notification) {
  return (notification->_initializedfields[ATCLIENT_ATNOTIFICATION_ID_INDEX] & ATCLIENT_ATNOTIFICATION_ID_INITIALIZED);
}

bool atclient_atnotification_is_from_initialized(const atclient_atnotification *notification) {
  return (notification->_initializedfields[ATCLIENT_ATNOTIFICATION_FROM_INDEX] &
          ATCLIENT_ATNOTIFICATION_FROM_INITIALIZED);
}

bool atclient_atnotification_is_to_initialized(const atclient_atnotification *notification) {
  return (notification->_initializedfields[ATCLIENT_ATNOTIFICATION_TO_INDEX] & ATCLIENT_ATNOTIFICATION_TO_INITIALIZED);
}

bool atclient_atnotification_is_key_initialized(const atclient_atnotification *notification) {
  return (notification->_initializedfields[ATCLIENT_ATNOTIFICATION_KEY_INDEX] &
          ATCLIENT_ATNOTIFICATION_KEY_INITIALIZED);
}

bool atclient_atnotification_is_value_initialized(const atclient_atnotification *notification) {
  return (notification->_initializedfields[ATCLIENT_ATNOTIFICATION_VALUE_INDEX] &
          ATCLIENT_ATNOTIFICATION_VALUE_INITIALIZED);
}

bool atclient_atnotification_is_operation_initialized(const atclient_atnotification *notification) {
  return (notification->_initializedfields[ATCLIENT_ATNOTIFICATION_OPERATION_INDEX] &
          ATCLIENT_ATNOTIFICATION_OPERATION_INITIALIZED);
}

bool atclient_atnotification_is_epochmillis_initialized(const atclient_atnotification *notification) {
  return (notification->_initializedfields[ATCLIENT_ATNOTIFICATION_EPOCHMILLIS_INDEX] &
          ATCLIENT_ATNOTIFICATION_EPOCHMILLIS_INITIALIZED);
}

bool atclient_atnotification_is_messagetype_initialized(const atclient_atnotification *notification) {
  return (notification->_initializedfields[ATCLIENT_ATNOTIFICATION_MESSAGETYPE_INDEX] &
          ATCLIENT_ATNOTIFICATION_MESSAGETYPE_INITIALIZED);
}

bool atclient_atnotification_is_isencrypted_initialized(const atclient_atnotification *notification) {
  return (notification->_initializedfields[ATCLIENT_ATNOTIFICATION_ISENCRYPTED_INDEX] &
          ATCLIENT_ATNOTIFICATION_ISENCRYPTED_INITIALIZED);
}

bool atclient_atnotification_is_enckeyname_initialized(const atclient_atnotification *notification) {
  return (notification->_initializedfields[ATCLIENT_ATNOTIFICATION_ENCKEYNAME_INDEX] &
          ATCLIENT_ATNOTIFICATION_ENCKEYNAME_INITIALIZED);
}

bool atclient_atnotification_is_encalgo_initialized(const atclient_atnotification *notification) {
  return (notification->_initializedfields[ATCLIENT_ATNOTIFICATION_ENCALGO_INDEX] &
          ATCLIENT_ATNOTIFICATION_ENCALGO_INITIALIZED);
}

bool atclient_atnotification_is_ivnonce_initialized(const atclient_atnotification *notification) {
  return (notification->_initializedfields[ATCLIENT_ATNOTIFICATION_IVNONCE_INDEX] &
          ATCLIENT_ATNOTIFICATION_IVNONCE_INITIALIZED);
}

bool atclient_atnotification_is_skeenckeyname_initialized(const atclient_atnotification *notification) {
  return (notification->_initializedfields[ATCLIENT_ATNOTIFICATION_SKEENCKEYNAME_INDEX] &
          ATCLIENT_ATNOTIFICATION_SKEENCKEYNAME_INITIALIZED);
}

bool atclient_atnotification_is_skeencalgo_initialized(const atclient_atnotification *notification) {
  return (notification->_initializedfields[ATCLIENT_ATNOTIFICATION_SKEENCALGO_INDEX] &
          ATCLIENT_ATNOTIFICATION_SKEENCALGO_INITIALIZED);
}

bool atclient_atnotification_is_decryptedvalue_initialized(const atclient_atnotification *notification) {
  return (notification->_initializedfields[ATCLIENT_ATNOTIFICATION_DECRYPTEDVALUE_INDEX] &
          ATCLIENT_ATNOTIFICATION_DECRYPTEDVALUE_INITIALIZED);
}

void atclient_atnotification_id_set_initialized(atclient_atnotification *notification, bool initialized) {
  if (initialized) {
    notification->_initializedfields[ATCLIENT_ATNOTIFICATION_ID_INDEX] |= ATCLIENT_ATNOTIFICATION_ID_INITIALIZED;
  } else {
    notification->_initializedfields[ATCLIENT_ATNOTIFICATION_ID_INDEX] &= ~ATCLIENT_ATNOTIFICATION_ID_INITIALIZED;
  }
}

void atclient_atnotification_from_set_initialized(atclient_atnotification *notification, bool initialized) {
  if (initialized) {
    notification->_initializedfields[ATCLIENT_ATNOTIFICATION_FROM_INDEX] |= ATCLIENT_ATNOTIFICATION_FROM_INITIALIZED;
  } else {
    notification->_initializedfields[ATCLIENT_ATNOTIFICATION_FROM_INDEX] &= ~ATCLIENT_ATNOTIFICATION_FROM_INITIALIZED;
  }
}

void atclient_atnotification_to_set_initialized(atclient_atnotification *notification, bool initialized) {
  if (initialized) {
    notification->_initializedfields[ATCLIENT_ATNOTIFICATION_TO_INDEX] |= ATCLIENT_ATNOTIFICATION_TO_INITIALIZED;
  } else {
    notification->_initializedfields[ATCLIENT_ATNOTIFICATION_TO_INDEX] &= ~ATCLIENT_ATNOTIFICATION_TO_INITIALIZED;
  }
}

void atclient_atnotification_key_set_initialized(atclient_atnotification *notification, bool initialized) {
  if (initialized) {
    notification->_initializedfields[ATCLIENT_ATNOTIFICATION_KEY_INDEX] |= ATCLIENT_ATNOTIFICATION_KEY_INITIALIZED;
  } else {
    notification->_initializedfields[ATCLIENT_ATNOTIFICATION_KEY_INDEX] &= ~ATCLIENT_ATNOTIFICATION_KEY_INITIALIZED;
  }
}

void atclient_atnotification_value_set_initialized(atclient_atnotification *notification, bool initialized) {
  if (initialized) {
    notification->_initializedfields[ATCLIENT_ATNOTIFICATION_VALUE_INDEX] |= ATCLIENT_ATNOTIFICATION_VALUE_INITIALIZED;
  } else {
    notification->_initializedfields[ATCLIENT_ATNOTIFICATION_VALUE_INDEX] &= ~ATCLIENT_ATNOTIFICATION_VALUE_INITIALIZED;
  }
}

void atclient_atnotification_operation_set_initialized(atclient_atnotification *notification, bool initialized) {
  if (initialized) {
    notification->_initializedfields[ATCLIENT_ATNOTIFICATION_OPERATION_INDEX] |=
        ATCLIENT_ATNOTIFICATION_OPERATION_INITIALIZED;
  } else {
    notification->_initializedfields[ATCLIENT_ATNOTIFICATION_OPERATION_INDEX] &=
        ~ATCLIENT_ATNOTIFICATION_OPERATION_INITIALIZED;
  }
}

void atclient_atnotification_epochmillis_set_initialized(atclient_atnotification *notification, bool initialized) {
  if (initialized) {
    notification->_initializedfields[ATCLIENT_ATNOTIFICATION_EPOCHMILLIS_INDEX] |=
        ATCLIENT_ATNOTIFICATION_EPOCHMILLIS_INITIALIZED;
  } else {
    notification->_initializedfields[ATCLIENT_ATNOTIFICATION_EPOCHMILLIS_INDEX] &=
        ~ATCLIENT_ATNOTIFICATION_EPOCHMILLIS_INITIALIZED;
  }
}

void atclient_atnotification_messagetype_set_initialized(atclient_atnotification *notification, bool initialized) {
  if (initialized) {
    notification->_initializedfields[ATCLIENT_ATNOTIFICATION_MESSAGETYPE_INDEX] |=
        ATCLIENT_ATNOTIFICATION_MESSAGETYPE_INITIALIZED;
  } else {
    notification->_initializedfields[0] &= ~ATCLIENT_ATNOTIFICATION_MESSAGETYPE_INITIALIZED;
  }
}

void atclient_atnotification_isencrypted_set_initialized(atclient_atnotification *notification, bool initialized) {
  if (initialized) {
    notification->_initializedfields[ATCLIENT_ATNOTIFICATION_ISENCRYPTED_INDEX] |=
        ATCLIENT_ATNOTIFICATION_ISENCRYPTED_INITIALIZED;
  } else {
    notification->_initializedfields[ATCLIENT_ATNOTIFICATION_ISENCRYPTED_INDEX] &=
        ~ATCLIENT_ATNOTIFICATION_ISENCRYPTED_INITIALIZED;
  }
}

void atclient_atnotification_enckeyname_set_initialized(atclient_atnotification *notification, bool initialized) {
  if (initialized) {
    notification->_initializedfields[ATCLIENT_ATNOTIFICATION_ENCKEYNAME_INDEX] |=
        ATCLIENT_ATNOTIFICATION_ENCKEYNAME_INITIALIZED;
  } else {
    notification->_initializedfields[1] &= ~ATCLIENT_ATNOTIFICATION_ENCKEYNAME_INITIALIZED;
  }
}

void atclient_atnotification_encalgo_set_initialized(atclient_atnotification *notification, bool initialized) {
  if (initialized) {
    notification->_initializedfields[ATCLIENT_ATNOTIFICATION_ENCALGO_INDEX] |=
        ATCLIENT_ATNOTIFICATION_ENCALGO_INITIALIZED;
  } else {
    notification->_initializedfields[ATCLIENT_ATNOTIFICATION_ENCALGO_INDEX] &=
        ~ATCLIENT_ATNOTIFICATION_ENCALGO_INITIALIZED;
  }
}

void atclient_atnotification_ivnonce_set_initialized(atclient_atnotification *notification, bool initialized) {
  if (initialized) {
    notification->_initializedfields[ATCLIENT_ATNOTIFICATION_IVNONCE_INDEX] |=
        ATCLIENT_ATNOTIFICATION_IVNONCE_INITIALIZED;
  } else {
    notification->_initializedfields[ATCLIENT_ATNOTIFICATION_IVNONCE_INDEX] &=
        ~ATCLIENT_ATNOTIFICATION_IVNONCE_INITIALIZED;
  }
}

void atclient_atnotification_skeenckeyname_set_initialized(atclient_atnotification *notification, bool initialized) {
  if (initialized) {
    notification->_initializedfields[ATCLIENT_ATNOTIFICATION_SKEENCKEYNAME_INDEX] |=
        ATCLIENT_ATNOTIFICATION_SKEENCKEYNAME_INITIALIZED;
  } else {
    notification->_initializedfields[ATCLIENT_ATNOTIFICATION_SKEENCKEYNAME_INDEX] &=
        ~ATCLIENT_ATNOTIFICATION_SKEENCKEYNAME_INITIALIZED;
  }
}

void atclient_atnotification_skeencalgo_set_initialized(atclient_atnotification *notification, bool initialized) {
  if (initialized) {
    notification->_initializedfields[ATCLIENT_ATNOTIFICATION_SKEENCALGO_INDEX] |=
        ATCLIENT_ATNOTIFICATION_SKEENCALGO_INITIALIZED;
  } else {
    notification->_initializedfields[ATCLIENT_ATNOTIFICATION_SKEENCALGO_INDEX] &=
        ~ATCLIENT_ATNOTIFICATION_SKEENCALGO_INITIALIZED;
  }
}

void atclient_atnotification_decryptedvalue_set_initialized(atclient_atnotification *notification, bool initialized) {
  if (initialized) {
    notification->_initializedfields[ATCLIENT_ATNOTIFICATION_DECRYPTEDVALUE_INDEX] |=
        ATCLIENT_ATNOTIFICATION_DECRYPTEDVALUE_INITIALIZED;
  } else {
    notification->_initializedfields[ATCLIENT_ATNOTIFICATION_DECRYPTEDVALUE_INDEX] &=
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
  if(atclient_atnotification_is_to_initialized(notification)) {
    free(notification->to);
  }
  notification->to = NULL;
  atclient_atnotification_to_set_initialized(notification, false);
}
void atclient_atnotification_unset_key(atclient_atnotification *notification) {
  if(atclient_atnotification_is_key_initialized(notification)) {
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
  if(atclient_atnotification_is_operation_initialized(notification)) {
    free(notification->operation);
  }
  notification->operation = NULL;
  atclient_atnotification_operation_set_initialized(notification, false);
}
void atclient_atnotification_unset_epochmillis(atclient_atnotification *notification) {
  notification->epochMillis = 0;
  atclient_atnotification_epochmillis_set_initialized(notification, false);
}

void atclient_atnotification_unset_messagetype(atclient_atnotification *notification) {
  if(atclient_atnotification_is_messagetype_initialized(notification)) {
    free(notification->messageType);
  }
  notification->messageType = NULL;
  atclient_atnotification_messagetype_set_initialized(notification, false);
}

void atclient_atnotification_unset_isencrypted(atclient_atnotification *notification) {
  notification->isEncrypted = false;
  atclient_atnotification_isencrypted_set_initialized(notification, false);
}

void atclient_atnotification_unset_enckeyname(atclient_atnotification *notification) {
  if(atclient_atnotification_is_enckeyname_initialized(notification)) {
    free(notification->encKeyName);
  }
  notification->encKeyName = NULL;
  atclient_atnotification_enckeyname_set_initialized(notification, false);
}

void atclient_atnotification_unset_encalgo(atclient_atnotification *notification) {
  if(atclient_atnotification_is_encalgo_initialized(notification)) {
    free(notification->encAlgo);
  }
  notification->encAlgo = NULL;
  atclient_atnotification_encalgo_set_initialized(notification, false);
}

void atclient_atnotification_unset_ivnonce(atclient_atnotification *notification) {
  if(atclient_atnotification_is_ivnonce_initialized(notification)) {
    free(notification->ivNonce);
  }
  notification->ivNonce = NULL;
  atclient_atnotification_ivnonce_set_initialized(notification, false);
}

void atclient_atnotification_unset_skeenckeyname(atclient_atnotification *notification) {
  if(atclient_atnotification_is_skeenckeyname_initialized(notification)) {
    free(notification->skeEncKeyName);
  }
  notification->skeEncKeyName = NULL;
  atclient_atnotification_skeenckeyname_set_initialized(notification, false);
}

void atclient_atnotification_unset_skeencalgo(atclient_atnotification *notification) {
  if(atclient_atnotification_is_skeencalgo_initialized(notification)) {
    free(notification->skeEncAlgo);
  }
  notification->skeEncAlgo = NULL;
  atclient_atnotification_skeencalgo_set_initialized(notification, false);
}

void atclient_atnotification_unset_decryptedvalue(atclient_atnotification *notification) {
  if(atclient_atnotification_is_decryptedvalue_initialized(notification)) {
    free(notification->decryptedvalue);
  }
  notification->decryptedvalue = NULL;
  atclient_atnotification_decryptedvalue_set_initialized(notification, false);
}

int atclient_atnotification_set_id(atclient_atnotification *notification, const char *id, const size_t idlen) {
  int ret = 1;
  if (atclient_atnotification_is_id_initialized(notification)) {
    atclient_atnotification_unset_id(notification);
  }
  notification->id = malloc(sizeof(char) * (idlen + 1));
  if (notification->id == NULL) {
    ret = 1;
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "Failed to allocate memory for notification id\n");
    goto exit;
  }
  memcpy(notification->id, id, idlen);
  *(notification->id + idlen) = '\0';
  atclient_atnotification_id_set_initialized(notification, true);
  ret = 0;
  goto exit;
exit: { return ret; }
}

int atclient_atnotification_set_from(atclient_atnotification *notification, const char *from, const size_t fromlen) {
  int ret = 1;
  if (atclient_atnotification_is_from_initialized(notification)) {
    atclient_atnotification_unset_from(notification);
  }
  notification->from = malloc(sizeof(char) * (fromlen + 1));
  if (notification->from == NULL) {
    ret = 1;
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "Failed to allocate memory for notification from\n");
    goto exit;
  }
  memcpy(notification->from, from, fromlen);
  *(notification->from + fromlen) = '\0';
  atclient_atnotification_from_set_initialized(notification, true);
  ret = 0;
  goto exit;
exit: { return ret; }
}

int atclient_atnotification_set_to(atclient_atnotification *notification, const char *to, const size_t tolen) {
  int ret = 1;
  if (atclient_atnotification_is_to_initialized(notification)) {
    atclient_atnotification_unset_to(notification);
  }
  notification->to = malloc(sizeof(char) * (tolen + 1));
  if (notification->to == NULL) {
    ret = 1;
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "Failed to allocate memory for notification to\n");
    goto exit;
  }
  memcpy(notification->to, to, tolen);
  *(notification->to + tolen) = '\0';
  atclient_atnotification_to_set_initialized(notification, true);
  ret = 0;
  goto exit;
exit: { return ret; }
}

int atclient_atnotification_set_key(atclient_atnotification *notification, const char *key, const size_t keylen) {
  int ret = 1;
  if (atclient_atnotification_is_key_initialized(notification)) {
    atclient_atnotification_unset_key(notification);
  }
  notification->key = malloc(sizeof(char) * (keylen + 1));
  if (notification->key == NULL) {
    ret = 1;
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "Failed to allocate memory for notification key\n");
    goto exit;
  }
  memcpy(notification->key, key, keylen);
  *(notification->key + keylen) = '\0';
  atclient_atnotification_key_set_initialized(notification, true);
  goto exit;
exit: { return ret; }
}

int atclient_atnotification_set_value(atclient_atnotification *notification, const char *value, const size_t valuelen) {
  int ret = 1;
  if (atclient_atnotification_is_value_initialized(notification)) {
    atclient_atnotification_unset_value(notification);
  }
  notification->value = malloc(sizeof(char) * (valuelen + 1));
  if (notification->value == NULL) {
    ret = 1;
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "Failed to allocate memory for notification value\n");
    goto exit;
  }
  memcpy(notification->value, value, valuelen);
  *(notification->value + valuelen) = '\0';
  atclient_atnotification_value_set_initialized(notification, true);
  ret = 0;
  goto exit;
exit: { return ret; }
}

int atclient_atnotification_set_operation(atclient_atnotification *notification, const char *operation,
                                          const size_t operationlen) {
  int ret = 1;
  if (atclient_atnotification_is_operation_initialized(notification)) {
    atclient_atnotification_unset_operation(notification);
  }
  notification->operation = malloc(sizeof(char) * (operationlen + 1));
  if (notification->operation == NULL) {
    ret = 1;
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "Failed to allocate memory for notification operation\n");
    goto exit;
  }
  memcpy(notification->operation, operation, operationlen);
  *(notification->operation + operationlen) = '\0';
  atclient_atnotification_operation_set_initialized(notification, true);
  ret = 0;
  goto exit;
exit: { return ret; }
}

int atclient_atnotification_set_epochmillis(atclient_atnotification *notification, const size_t epochMillis) {
  if (atclient_atnotification_is_epochmillis_initialized(notification)) {
    atclient_atnotification_unset_epochmillis(notification);
  }
  notification->epochMillis = epochMillis;
  atclient_atnotification_epochmillis_set_initialized(notification, true);
  return 0;
}

int atclient_atnotification_set_messagetype(atclient_atnotification *notification, const char *messageType,
                                            const size_t messageTypelen) {
  int ret = 1;
  if (atclient_atnotification_is_messagetype_initialized(notification)) {
    atclient_atnotification_unset_messagetype(notification);
  }
  notification->messageType = malloc(sizeof(char) * (messageTypelen + 1));
  if (notification->messageType == NULL) {
    ret = 1;
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "Failed to allocate memory for notification messageType\n");
    goto exit;
  }
  memcpy(notification->messageType, messageType, messageTypelen);
  *(notification->messageType + messageTypelen) = '\0';
  atclient_atnotification_messagetype_set_initialized(notification, true);
  ret = 0;
  goto exit;
exit: { return ret; }
}

int atclient_atnotification_set_isencrypted(atclient_atnotification *notification, const bool isEncrypted) {
  if (atclient_atnotification_is_isencrypted_initialized(notification)) {
    atclient_atnotification_unset_isencrypted(notification);
  }
  notification->isEncrypted = isEncrypted;
  atclient_atnotification_isencrypted_set_initialized(notification, true);
  return 0;
}

int atclient_atnotification_set_enckeyname(atclient_atnotification *notification, const char *encKeyName,
                                           const size_t encKeyNamelen) {
  int ret = 1;
  if (atclient_atnotification_is_enckeyname_initialized(notification)) {
    atclient_atnotification_unset_enckeyname(notification);
  }
  notification->encKeyName = malloc(sizeof(char) * (encKeyNamelen + 1));
  if (notification->encKeyName == NULL) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "Failed to allocate memory for notification encKeyName\n");
    goto exit;
  }
  memcpy(notification->encKeyName, encKeyName, encKeyNamelen);
  *(notification->encKeyName + encKeyNamelen) = '\0';
  atclient_atnotification_enckeyname_set_initialized(notification, true);
  ret = 0;
  goto exit;
exit: { return ret; }
}

int atclient_atnotification_set_encalgo(atclient_atnotification *notification, const char *encAlgo,
                                        const size_t encAlgolen) {
  int ret = 1;
  if (atclient_atnotification_is_encalgo_initialized(notification)) {
    atclient_atnotification_unset_encalgo(notification);
  }
  notification->encAlgo = malloc(sizeof(char) * (encAlgolen + 1));
  memcpy(notification->encAlgo, encAlgo, encAlgolen);
  *(notification->encAlgo + encAlgolen) = '\0';
  atclient_atnotification_encalgo_set_initialized(notification, true);
  ret = 0;
  goto exit;
exit: { return ret; }
}

int atclient_atnotification_set_ivnonce(atclient_atnotification *notification, const char *ivNonce,
                                        const size_t ivNoncelen) {
  int ret = 1;
  if (atclient_atnotification_is_ivnonce_initialized(notification)) {
    atclient_atnotification_unset_ivnonce(notification);
  }
  notification->ivNonce = malloc(sizeof(char) * (ivNoncelen + 1));
  if (notification->ivNonce == NULL) {
    ret = 1;
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "Failed to allocate memory for notification ivNonce\n");
    goto exit;
  }
  memcpy(notification->ivNonce, ivNonce, ivNoncelen);
  *(notification->ivNonce + ivNoncelen) = '\0';
  atclient_atnotification_ivnonce_set_initialized(notification, true);
  ret = 0;
  goto exit;
exit: { return ret; }
}

int atclient_atnotification_set_skeenckeyname(atclient_atnotification *notification, const char *skeEncKeyName,
                                              const size_t skeEncKeyNamelen) {
  int ret = 1;
  if (atclient_atnotification_is_skeenckeyname_initialized(notification)) {
    atclient_atnotification_unset_skeenckeyname(notification);
  }
  notification->skeEncKeyName = malloc(sizeof(char) * (skeEncKeyNamelen + 1));
  if (notification->skeEncKeyName == NULL) {
    ret = 1;
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "Failed to allocate memory for notification skeEncKeyName\n");
    goto exit;
  }
  memcpy(notification->skeEncKeyName, skeEncKeyName, skeEncKeyNamelen);
  *(notification->skeEncKeyName + skeEncKeyNamelen) = '\0';
  atclient_atnotification_skeenckeyname_set_initialized(notification, true);
  ret = 0;
  goto exit;
exit: { return ret; }
}

int atclient_atnotification_set_skeencalgo(atclient_atnotification *notification, const char *skeEncAlgo,
                                           const size_t skeEncAlgolen) {
  int ret = 1;
  if (atclient_atnotification_is_skeencalgo_initialized(notification)) {
    atclient_atnotification_unset_skeencalgo(notification);
  }
  notification->skeEncAlgo = malloc(sizeof(char) * (skeEncAlgolen + 1));
  if (notification->skeEncAlgo == NULL) {
    ret = 1;
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "Failed to allocate memory for notification skeEncAlgo\n");
    goto exit;
  }
  memcpy(notification->skeEncAlgo, skeEncAlgo, skeEncAlgolen);
  *(notification->skeEncAlgo + skeEncAlgolen) = '\0';
  atclient_atnotification_skeencalgo_set_initialized(notification, true);
  ret = 0;
  goto exit;
exit: { return ret; }
}

int atclient_atnotification_set_decryptedvalue(atclient_atnotification *notification,
                                               const char *decryptedvalue, const size_t decryptedvaluelen) {
  int ret = 1;
  if (atclient_atnotification_is_decryptedvalue_initialized(notification)) {
    atclient_atnotification_unset_decryptedvalue(notification);
  }
  notification->decryptedvalue = malloc(sizeof(unsigned char) * (decryptedvaluelen + 1));
  if (notification->decryptedvalue == NULL) {
    ret = 1;
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "Failed to allocate memory for notification decryptedvalue\n");
    goto exit;
  }
  memcpy(notification->decryptedvalue, decryptedvalue, decryptedvaluelen);
  notification->decryptedvalue[decryptedvaluelen] = '\0';
  atclient_atnotification_decryptedvalue_set_initialized(notification, true);
  ret = 0;
  goto exit;
exit: { return ret; }
}
