#include "atclient/atnotification.h"
#include <atlogger/atlogger.h>
#include <stdlib.h>
#include <string.h>

#define TAG "atnotification"

void atclient_atnotification_init(atclient_atnotification *notification) {
  memset(notification, 0, sizeof(atclient_atnotification));
}

void atclient_atnotification_free(atclient_atnotification *notification) {
  if (atclient_atnotification_id_is_initialized(notification)) {
    atclient_atnotification_unset_id(notification);
  }
  if (atclient_atnotification_from_is_initialized(notification)) {
    atclient_atnotification_unset_from(notification);
  }
  if (atclient_atnotification_to_is_initialized(notification)) {
    atclient_atnotification_unset_to(notification);
  }
  if (atclient_atnotification_key_is_initialized(notification)) {
    atclient_atnotification_unset_key(notification);
  }
  if (atclient_atnotification_value_is_initialized(notification)) {
    atclient_atnotification_unset_value(notification);
  }
  if (atclient_atnotification_operation_is_initialized(notification)) {
    atclient_atnotification_unset_operation(notification);
  }
  if (atclient_atnotification_epochMillis_is_initialized(notification)) {
    atclient_atnotification_unset_epochMillis(notification);
  }
  if (atclient_atnotification_messageType_is_initialized(notification)) {
    atclient_atnotification_unset_messageType(notification);
  }
  if (atclient_atnotification_isEncrypted_is_initialized(notification)) {
    atclient_atnotification_unset_isEncrypted(notification);
  }
  if (atclient_atnotification_encKeyName_is_initialized(notification)) {
    atclient_atnotification_unset_encKeyName(notification);
  }
  if (atclient_atnotification_encAlgo_is_initialized(notification)) {
    atclient_atnotification_unset_encAlgo(notification);
  }
  if (atclient_atnotification_ivNonce_is_initialized(notification)) {
    atclient_atnotification_unset_ivNonce(notification);
  }
  if (atclient_atnotification_skeEncKeyName_is_initialized(notification)) {
    atclient_atnotification_unset_skeEncKeyName(notification);
  }
  if (atclient_atnotification_skeEncAlgo_is_initialized(notification)) {
    atclient_atnotification_unset_skeEncAlgo(notification);
  }
  if (atclient_atnotification_decryptedvalue_is_initialized(notification)) {
    atclient_atnotification_unset_decryptedvalue(notification);
  }
}

bool atclient_atnotification_id_is_initialized(const atclient_atnotification *notification) {
  return (notification->_initializedfields[ATCLIENT_ATNOTIFICATION_ID_INDEX] & ATCLIENT_ATNOTIFICATION_ID_INITIALIZED);
}

bool atclient_atnotification_from_is_initialized(const atclient_atnotification *notification) {
  return (notification->_initializedfields[ATCLIENT_ATNOTIFICATION_FROM_INDEX] &
          ATCLIENT_ATNOTIFICATION_FROM_INITIALIZED);
}

bool atclient_atnotification_to_is_initialized(const atclient_atnotification *notification) {
  return (notification->_initializedfields[ATCLIENT_ATNOTIFICATION_TO_INDEX] & ATCLIENT_ATNOTIFICATION_TO_INITIALIZED);
}

bool atclient_atnotification_key_is_initialized(const atclient_atnotification *notification) {
  return (notification->_initializedfields[ATCLIENT_ATNOTIFICATION_KEY_INDEX] &
          ATCLIENT_ATNOTIFICATION_KEY_INITIALIZED);
}

bool atclient_atnotification_value_is_initialized(const atclient_atnotification *notification) {
  return (notification->_initializedfields[ATCLIENT_ATNOTIFICATION_VALUE_INDEX] &
          ATCLIENT_ATNOTIFICATION_VALUE_INITIALIZED);
}

bool atclient_atnotification_operation_is_initialized(const atclient_atnotification *notification) {
  return (notification->_initializedfields[ATCLIENT_ATNOTIFICATION_OPERATION_INDEX] &
          ATCLIENT_ATNOTIFICATION_OPERATION_INITIALIZED);
}

bool atclient_atnotification_epochMillis_is_initialized(const atclient_atnotification *notification) {
  return (notification->_initializedfields[ATCLIENT_ATNOTIFICATION_EPOCHMILLIS_INDEX] &
          ATCLIENT_ATNOTIFICATION_EPOCHMILLIS_INITIALIZED);
}

bool atclient_atnotification_messageType_is_initialized(const atclient_atnotification *notification) {
  return (notification->_initializedfields[ATCLIENT_ATNOTIFICATION_MESSAGETYPE_INDEX] &
          ATCLIENT_ATNOTIFICATION_MESSAGETYPE_INITIALIZED);
}

bool atclient_atnotification_isEncrypted_is_initialized(const atclient_atnotification *notification) {
  return (notification->_initializedfields[ATCLIENT_ATNOTIFICATION_ISENCRYPTED_INDEX] &
          ATCLIENT_ATNOTIFICATION_ISENCRYPTED_INITIALIZED);
}

bool atclient_atnotification_encKeyName_is_initialized(const atclient_atnotification *notification) {
  return (notification->_initializedfields[ATCLIENT_ATNOTIFICATION_ENCKEYNAME_INDEX] &
          ATCLIENT_ATNOTIFICATION_ENCKEYNAME_INITIALIZED);
}

bool atclient_atnotification_encAlgo_is_initialized(const atclient_atnotification *notification) {
  return (notification->_initializedfields[ATCLIENT_ATNOTIFICATION_ENCALGO_INDEX] &
          ATCLIENT_ATNOTIFICATION_ENCALGO_INITIALIZED);
}

bool atclient_atnotification_ivNonce_is_initialized(const atclient_atnotification *notification) {
  return (notification->_initializedfields[ATCLIENT_ATNOTIFICATION_IVNONCE_INDEX] &
          ATCLIENT_ATNOTIFICATION_IVNONCE_INITIALIZED);
}

bool atclient_atnotification_skeEncKeyName_is_initialized(const atclient_atnotification *notification) {
  return (notification->_initializedfields[ATCLIENT_ATNOTIFICATION_SKEENCKEYNAME_INDEX] &
          ATCLIENT_ATNOTIFICATION_SKEENCKEYNAME_INITIALIZED);
}

bool atclient_atnotification_skeEncAlgo_is_initialized(const atclient_atnotification *notification) {
  return (notification->_initializedfields[ATCLIENT_ATNOTIFICATION_SKEENCALGO_INDEX] &
          ATCLIENT_ATNOTIFICATION_SKEENCALGO_INITIALIZED);
}

bool atclient_atnotification_decryptedvalue_is_initialized(const atclient_atnotification *notification) {
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

void atclient_atnotification_epochMillis_set_initialized(atclient_atnotification *notification, bool initialized) {
  if (initialized) {
    notification->_initializedfields[ATCLIENT_ATNOTIFICATION_EPOCHMILLIS_INDEX] |=
        ATCLIENT_ATNOTIFICATION_EPOCHMILLIS_INITIALIZED;
  } else {
    notification->_initializedfields[ATCLIENT_ATNOTIFICATION_EPOCHMILLIS_INDEX] &=
        ~ATCLIENT_ATNOTIFICATION_EPOCHMILLIS_INITIALIZED;
  }
}

void atclient_atnotification_messageType_set_initialized(atclient_atnotification *notification, bool initialized) {
  if (initialized) {
    notification->_initializedfields[ATCLIENT_ATNOTIFICATION_MESSAGETYPE_INDEX] |=
        ATCLIENT_ATNOTIFICATION_MESSAGETYPE_INITIALIZED;
  } else {
    notification->_initializedfields[0] &= ~ATCLIENT_ATNOTIFICATION_MESSAGETYPE_INITIALIZED;
  }
}

void atclient_atnotification_isEncrypted_set_initialized(atclient_atnotification *notification, bool initialized) {
  if (initialized) {
    notification->_initializedfields[ATCLIENT_ATNOTIFICATION_ISENCRYPTED_INDEX] |=
        ATCLIENT_ATNOTIFICATION_ISENCRYPTED_INITIALIZED;
  } else {
    notification->_initializedfields[ATCLIENT_ATNOTIFICATION_ISENCRYPTED_INDEX] &=
        ~ATCLIENT_ATNOTIFICATION_ISENCRYPTED_INITIALIZED;
  }
}

void atclient_atnotification_encKeyName_set_initialized(atclient_atnotification *notification, bool initialized) {
  if (initialized) {
    notification->_initializedfields[ATCLIENT_ATNOTIFICATION_ENCKEYNAME_INDEX] |=
        ATCLIENT_ATNOTIFICATION_ENCKEYNAME_INITIALIZED;
  } else {
    notification->_initializedfields[1] &= ~ATCLIENT_ATNOTIFICATION_ENCKEYNAME_INITIALIZED;
  }
}

void atclient_atnotification_encAlgo_set_initialized(atclient_atnotification *notification, bool initialized) {
  if (initialized) {
    notification->_initializedfields[ATCLIENT_ATNOTIFICATION_ENCALGO_INDEX] |=
        ATCLIENT_ATNOTIFICATION_ENCALGO_INITIALIZED;
  } else {
    notification->_initializedfields[ATCLIENT_ATNOTIFICATION_ENCALGO_INDEX] &=
        ~ATCLIENT_ATNOTIFICATION_ENCALGO_INITIALIZED;
  }
}

void atclient_atnotification_ivNonce_set_initialized(atclient_atnotification *notification, bool initialized) {
  if (initialized) {
    notification->_initializedfields[ATCLIENT_ATNOTIFICATION_IVNONCE_INDEX] |=
        ATCLIENT_ATNOTIFICATION_IVNONCE_INITIALIZED;
  } else {
    notification->_initializedfields[ATCLIENT_ATNOTIFICATION_IVNONCE_INDEX] &=
        ~ATCLIENT_ATNOTIFICATION_IVNONCE_INITIALIZED;
  }
}

void atclient_atnotification_skeEncKeyName_set_initialized(atclient_atnotification *notification, bool initialized) {
  if (initialized) {
    notification->_initializedfields[ATCLIENT_ATNOTIFICATION_SKEENCKEYNAME_INDEX] |=
        ATCLIENT_ATNOTIFICATION_SKEENCKEYNAME_INITIALIZED;
  } else {
    notification->_initializedfields[ATCLIENT_ATNOTIFICATION_SKEENCKEYNAME_INDEX] &=
        ~ATCLIENT_ATNOTIFICATION_SKEENCKEYNAME_INITIALIZED;
  }
}

void atclient_atnotification_skeEncAlgo_set_initialized(atclient_atnotification *notification, bool initialized) {
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
  if (atclient_atnotification_id_is_initialized(notification)) {
    free(notification->id);
  }
  notification->id = NULL;
  atclient_atnotification_id_set_initialized(notification, false);
  atclient_atnotification_id_set_initialized(notification, false);
}

void atclient_atnotification_unset_from(atclient_atnotification *notification) {
  if (atclient_atnotification_from_is_initialized(notification)) {
    free(notification->from);
  }
  notification->from = NULL;
  atclient_atnotification_from_set_initialized(notification, false);
}

void atclient_atnotification_unset_to(atclient_atnotification *notification) {
  if(atclient_atnotification_to_is_initialized(notification)) {
    free(notification->to);
  }
  notification->to = NULL;
  atclient_atnotification_to_set_initialized(notification, false);
}
void atclient_atnotification_unset_key(atclient_atnotification *notification) {
  if(atclient_atnotification_key_is_initialized(notification)) {
    free(notification->key);
  }
  notification->key = NULL;
  atclient_atnotification_key_set_initialized(notification, false);
}
void atclient_atnotification_unset_value(atclient_atnotification *notification) {
  if (atclient_atnotification_value_is_initialized(notification)) {
    free(notification->value);
  }
    notification->value = NULL;
  atclient_atnotification_value_set_initialized(notification, false);
}
void atclient_atnotification_unset_operation(atclient_atnotification *notification) {
  if(atclient_atnotification_operation_is_initialized(notification)) {
    free(notification->operation);
  }
  notification->operation = NULL;
  atclient_atnotification_operation_set_initialized(notification, false);
}
void atclient_atnotification_unset_epochMillis(atclient_atnotification *notification) {
  notification->epochMillis = 0;
  atclient_atnotification_epochMillis_set_initialized(notification, false);
}

void atclient_atnotification_unset_messageType(atclient_atnotification *notification) {
  if(atclient_atnotification_messageType_is_initialized(notification)) {
    free(notification->messageType);
  }
  notification->messageType = NULL;
  atclient_atnotification_messageType_set_initialized(notification, false);
}

void atclient_atnotification_unset_isEncrypted(atclient_atnotification *notification) {
  notification->isEncrypted = false;
  atclient_atnotification_isEncrypted_set_initialized(notification, false);
}

void atclient_atnotification_unset_encKeyName(atclient_atnotification *notification) {
  if(atclient_atnotification_encKeyName_is_initialized(notification)) {
    free(notification->encKeyName);
  }
  notification->encKeyName = NULL;
  atclient_atnotification_encKeyName_set_initialized(notification, false);
}

void atclient_atnotification_unset_encAlgo(atclient_atnotification *notification) {
  if(atclient_atnotification_encAlgo_is_initialized(notification)) {
    free(notification->encAlgo);
  }
  notification->encAlgo = NULL;
  atclient_atnotification_encAlgo_set_initialized(notification, false);
}

void atclient_atnotification_unset_ivNonce(atclient_atnotification *notification) {
  if(atclient_atnotification_ivNonce_is_initialized(notification)) {
    free(notification->ivNonce);
  }
  notification->ivNonce = NULL;
  atclient_atnotification_ivNonce_set_initialized(notification, false);
}

void atclient_atnotification_unset_skeEncKeyName(atclient_atnotification *notification) {
  if(atclient_atnotification_skeEncKeyName_is_initialized(notification)) {
    free(notification->skeEncKeyName);
  }
  notification->skeEncKeyName = NULL;
  atclient_atnotification_skeEncKeyName_set_initialized(notification, false);
}

void atclient_atnotification_unset_skeEncAlgo(atclient_atnotification *notification) {
  if(atclient_atnotification_skeEncAlgo_is_initialized(notification)) {
    free(notification->skeEncAlgo);
  }
  notification->skeEncAlgo = NULL;
  atclient_atnotification_skeEncAlgo_set_initialized(notification, false);
}

void atclient_atnotification_unset_decryptedvalue(atclient_atnotification *notification) {
  if(atclient_atnotification_decryptedvalue_is_initialized(notification)) {
    free(notification->decryptedvalue);
  }
  notification->decryptedvalue = NULL;
  atclient_atnotification_decryptedvalue_set_initialized(notification, false);
}

int atclient_atnotification_set_id(atclient_atnotification *notification, const char *id, const size_t idlen) {
  int ret = 1;
  if (atclient_atnotification_id_is_initialized(notification)) {
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
  if (atclient_atnotification_from_is_initialized(notification)) {
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
  if (atclient_atnotification_to_is_initialized(notification)) {
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
  if (atclient_atnotification_key_is_initialized(notification)) {
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
  if (atclient_atnotification_value_is_initialized(notification)) {
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
  if (atclient_atnotification_operation_is_initialized(notification)) {
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

int atclient_atnotification_set_epochMillis(atclient_atnotification *notification, const size_t epochMillis) {
  if (atclient_atnotification_epochMillis_is_initialized(notification)) {
    atclient_atnotification_unset_epochMillis(notification);
  }
  notification->epochMillis = epochMillis;
  atclient_atnotification_epochMillis_set_initialized(notification, true);
  return 0;
}

int atclient_atnotification_set_messageType(atclient_atnotification *notification, const char *messageType,
                                            const size_t messageTypelen) {
  int ret = 1;
  if (atclient_atnotification_messageType_is_initialized(notification)) {
    atclient_atnotification_unset_messageType(notification);
  }
  notification->messageType = malloc(sizeof(char) * (messageTypelen + 1));
  if (notification->messageType == NULL) {
    ret = 1;
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "Failed to allocate memory for notification messageType\n");
    goto exit;
  }
  memcpy(notification->messageType, messageType, messageTypelen);
  *(notification->messageType + messageTypelen) = '\0';
  atclient_atnotification_messageType_set_initialized(notification, true);
  ret = 0;
  goto exit;
exit: { return ret; }
}

int atclient_atnotification_set_isEncrypted(atclient_atnotification *notification, const bool isEncrypted) {
  if (atclient_atnotification_isEncrypted_is_initialized(notification)) {
    atclient_atnotification_unset_isEncrypted(notification);
  }
  notification->isEncrypted = isEncrypted;
  atclient_atnotification_isEncrypted_set_initialized(notification, true);
  return 0;
}

int atclient_atnotification_set_encKeyName(atclient_atnotification *notification, const char *encKeyName,
                                           const size_t encKeyNamelen) {
  int ret = 1;
  if (atclient_atnotification_encKeyName_is_initialized(notification)) {
    atclient_atnotification_unset_encKeyName(notification);
  }
  notification->encKeyName = malloc(sizeof(char) * (encKeyNamelen + 1));
  if (notification->encKeyName == NULL) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "Failed to allocate memory for notification encKeyName\n");
    goto exit;
  }
  memcpy(notification->encKeyName, encKeyName, encKeyNamelen);
  *(notification->encKeyName + encKeyNamelen) = '\0';
  atclient_atnotification_encKeyName_set_initialized(notification, true);
  ret = 0;
  goto exit;
exit: { return ret; }
}

int atclient_atnotification_set_encAlgo(atclient_atnotification *notification, const char *encAlgo,
                                        const size_t encAlgolen) {
  int ret = 1;
  if (atclient_atnotification_encAlgo_is_initialized(notification)) {
    atclient_atnotification_unset_encAlgo(notification);
  }
  notification->encAlgo = malloc(sizeof(char) * (encAlgolen + 1));
  memcpy(notification->encAlgo, encAlgo, encAlgolen);
  *(notification->encAlgo + encAlgolen) = '\0';
  atclient_atnotification_encAlgo_set_initialized(notification, true);
  ret = 0;
  goto exit;
exit: { return ret; }
}

int atclient_atnotification_set_ivNonce(atclient_atnotification *notification, const char *ivNonce,
                                        const size_t ivNoncelen) {
  int ret = 1;
  if (atclient_atnotification_ivNonce_is_initialized(notification)) {
    atclient_atnotification_unset_ivNonce(notification);
  }
  notification->ivNonce = malloc(sizeof(char) * (ivNoncelen + 1));
  if (notification->ivNonce == NULL) {
    ret = 1;
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "Failed to allocate memory for notification ivNonce\n");
    goto exit;
  }
  memcpy(notification->ivNonce, ivNonce, ivNoncelen);
  *(notification->ivNonce + ivNoncelen) = '\0';
  atclient_atnotification_ivNonce_set_initialized(notification, true);
  ret = 0;
  goto exit;
exit: { return ret; }
}

int atclient_atnotification_set_skeEncKeyName(atclient_atnotification *notification, const char *skeEncKeyName,
                                              const size_t skeEncKeyNamelen) {
  int ret = 1;
  if (atclient_atnotification_skeEncKeyName_is_initialized(notification)) {
    atclient_atnotification_unset_skeEncKeyName(notification);
  }
  notification->skeEncKeyName = malloc(sizeof(char) * (skeEncKeyNamelen + 1));
  if (notification->skeEncKeyName == NULL) {
    ret = 1;
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "Failed to allocate memory for notification skeEncKeyName\n");
    goto exit;
  }
  memcpy(notification->skeEncKeyName, skeEncKeyName, skeEncKeyNamelen);
  *(notification->skeEncKeyName + skeEncKeyNamelen) = '\0';
  atclient_atnotification_skeEncKeyName_set_initialized(notification, true);
  ret = 0;
  goto exit;
exit: { return ret; }
}

int atclient_atnotification_set_skeEncAlgo(atclient_atnotification *notification, const char *skeEncAlgo,
                                           const size_t skeEncAlgolen) {
  int ret = 1;
  if (atclient_atnotification_skeEncAlgo_is_initialized(notification)) {
    atclient_atnotification_unset_skeEncAlgo(notification);
  }
  notification->skeEncAlgo = malloc(sizeof(char) * (skeEncAlgolen + 1));
  if (notification->skeEncAlgo == NULL) {
    ret = 1;
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "Failed to allocate memory for notification skeEncAlgo\n");
    goto exit;
  }
  memcpy(notification->skeEncAlgo, skeEncAlgo, skeEncAlgolen);
  *(notification->skeEncAlgo + skeEncAlgolen) = '\0';
  atclient_atnotification_skeEncAlgo_set_initialized(notification, true);
  ret = 0;
  goto exit;
exit: { return ret; }
}

int atclient_atnotification_set_decryptedvalue(atclient_atnotification *notification,
                                               const char *decryptedvalue, const size_t decryptedvaluelen) {
  int ret = 1;
  if (atclient_atnotification_decryptedvalue_is_initialized(notification)) {
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
