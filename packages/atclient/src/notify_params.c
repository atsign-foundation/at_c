#include "atclient/notify_params.h"
#include "atchops/aes.h"
#include "atclient/constants.h"
#include <atlogger/atlogger.h>
#include <stdlib.h>
#include <string.h>

#define TAG "atclient_notify_params"

void atclient_notify_params_init(atclient_notify_params *params) {
  memset(params, 0, sizeof(atclient_notify_params));
  params->id = NULL;
  params->atkey = NULL;
  params->value = NULL;
  params->operation = ATCLIENT_NOTIFY_OPERATION_NONE;
  params->message_type = ATCLIENT_NOTIFY_MESSAGE_TYPE_KEY;
  params->priority = ATCLIENT_NOTIFY_PRIORITY_LOW;
  params->strategy = ATCLIENT_NOTIFY_STRATEGY_ALL;
  params->latest_n = 1;
  params->notifier = ATCLIENT_DEFAULT_NOTIFIER;
  params->notification_expiry = 24 * 60 * 60 * 1000; // 24 hours in milliseconds
  params->should_encrypt = true;
  params->shared_encryption_key = NULL;
  memset(params->_initialized_fields, 0, sizeof(params->_initialized_fields));
}

void atclient_notify_params_free(atclient_notify_params *params) {
  atclient_notify_params_unset_id(params);
  atclient_notify_params_unset_atkey(params);
  atclient_notify_params_unset_value(params);
  atclient_notify_params_unset_operation(params);
  atclient_notify_params_unset_message_type(params);
  atclient_notify_params_unset_priority(params);
  atclient_notify_params_unset_strategy(params);
  atclient_notify_params_unset_latest_n(params);
  atclient_notify_params_unset_notifier(params);
  atclient_notify_params_unset_notification_expiry(params);
  atclient_notify_params_unset_should_encrypt(params);
  atclient_notify_params_unset_shared_encryption_key(params);
  memset(params, 0, sizeof(atclient_notify_params));
}

bool atclient_notify_params_is_id_initialized(const atclient_notify_params *params) {
  return params->_initialized_fields[ATCLIENT_NOTIFY_PARAMS_ID_INDEX] & ATCLIENT_NOTIFY_PARAMS_ID_INITIALIZED;
}

bool atclient_notify_params_is_atkey_initialized(const atclient_notify_params *params) {
  return params->_initialized_fields[ATCLIENT_NOTIFY_PARAMS_ATKEY_INDEX] & ATCLIENT_NOTIFY_PARAMS_ATKEY_INITIALIZED;
}

bool atclient_notify_params_is_value_initialized(const atclient_notify_params *params) {
  return params->_initialized_fields[ATCLIENT_NOTIFY_PARAMS_VALUE_INDEX] & ATCLIENT_NOTIFY_PARAMS_VALUE_INITIALIZED;
}

bool atclient_notify_params_is_should_encrypt_initialized(const atclient_notify_params *params) {
  return params->_initialized_fields[ATCLIENT_NOTIFY_PARAMS_SHOULD_ENCRYPT_INDEX] &
         ATCLIENT_NOTIFY_PARAMS_SHOULD_ENCRYPT_INITIALIZED;
}

bool atclient_notify_params_is_operation_initialized(const atclient_notify_params *params) {
  return params->_initialized_fields[ATCLIENT_NOTIFY_PARAMS_OPERATION_INDEX] &
         ATCLIENT_NOTIFY_PARAMS_OPERATION_INITIALIZED;
}

bool atclient_notify_params_is_message_type_initialized(const atclient_notify_params *params) {
  return params->_initialized_fields[ATCLIENT_NOTIFY_PARAMS_MESSAGE_TYPE_INDEX] &
         ATCLIENT_NOTIFY_PARAMS_MESSAGE_TYPE_INITIALIZED;
}

bool atclient_notify_params_is_priority_initialized(const const atclient_notify_params *params) {
  return params->_initialized_fields[ATCLIENT_NOTIFY_PARAMS_PRIORITY_INDEX] &
         ATCLIENT_NOTIFY_PARAMS_PRIORITY_INITIALIZED;
}

bool atclient_notify_params_is_strategy_initialized(atclient_notify_params *params) {
  return params->_initialized_fields[ATCLIENT_NOTIFY_PARAMS_STRATEGY_INDEX] &
         ATCLIENT_NOTIFY_PARAMS_STRATEGY_INITIALIZED;
}

bool atclient_notify_params_is_latest_n_initialized(const atclient_notify_params *params) {
  return params->_initialized_fields[ATCLIENT_NOTIFY_PARAMS_LATEST_N_INDEX] &
         ATCLIENT_NOTIFY_PARAMS_LATEST_N_INITIALIZED;
}

bool atclient_notify_params_is_notifier_initialized(const atclient_notify_params *params) {
  return params->_initialized_fields[ATCLIENT_NOTIFY_PARAMS_NOTIFIER_INDEX] &
         ATCLIENT_NOTIFY_PARAMS_NOTIFIER_INITIALIZED;
}

bool atclient_notify_params_is_notification_expiry_initialized(const atclient_notify_params *params) {
  return params->_initialized_fields[ATCLIENT_NOTIFY_PARAMS_NOTIFICATION_EXPIRY_INDEX] &
         ATCLIENT_NOTIFY_PARAMS_NOTIFICATION_EXPIRY_INITIALIZED;
}

bool atclient_notify_params_is_shared_encryption_key_initialized(const atclient_notify_params *params) {
  return params->_initialized_fields[ATCLIENT_NOTIFY_PARAMS_SHARED_ENCRYPTION_KEY_INDEX] &
         ATCLIENT_NOTIFY_PARAMS_SHARED_ENCRYPTION_KEY_INITIALIZED;
}

void atclient_notify_params_set_id_initialized(atclient_notify_params *params, const bool initialized) {
  if (initialized) {
    params->_initialized_fields[ATCLIENT_NOTIFY_PARAMS_ID_INDEX] |= ATCLIENT_NOTIFY_PARAMS_ID_INITIALIZED;
  } else {
    params->_initialized_fields[ATCLIENT_NOTIFY_PARAMS_ID_INDEX] &= ~ATCLIENT_NOTIFY_PARAMS_ID_INITIALIZED;
  }
}

void atclient_notify_params_set_atkey_initialized(atclient_notify_params *params, const bool initialized) {
  if (initialized) {
    params->_initialized_fields[ATCLIENT_NOTIFY_PARAMS_ATKEY_INDEX] |= ATCLIENT_NOTIFY_PARAMS_ATKEY_INITIALIZED;
  } else {
    params->_initialized_fields[ATCLIENT_NOTIFY_PARAMS_ATKEY_INDEX] &= ~ATCLIENT_NOTIFY_PARAMS_ATKEY_INITIALIZED;
  }
}

void atclient_notify_params_set_value_initialized(atclient_notify_params *params, const bool initialized) {
  if (initialized) {
    params->_initialized_fields[ATCLIENT_NOTIFY_PARAMS_VALUE_INDEX] |= ATCLIENT_NOTIFY_PARAMS_VALUE_INITIALIZED;
  } else {
    params->_initialized_fields[ATCLIENT_NOTIFY_PARAMS_VALUE_INDEX] &= ~ATCLIENT_NOTIFY_PARAMS_VALUE_INITIALIZED;
  }
}

void atclient_notify_params_set_should_encrypt_initialized(atclient_notify_params *params, const bool initialized) {
  if (initialized) {
    params->_initialized_fields[ATCLIENT_NOTIFY_PARAMS_SHOULD_ENCRYPT_INDEX] |=
        ATCLIENT_NOTIFY_PARAMS_SHOULD_ENCRYPT_INITIALIZED;
  } else {
    params->_initialized_fields[ATCLIENT_NOTIFY_PARAMS_SHOULD_ENCRYPT_INDEX] &=
        ~ATCLIENT_NOTIFY_PARAMS_SHOULD_ENCRYPT_INITIALIZED;
  }
}

void atclient_notify_params_set_operation_initialized(atclient_notify_params *params, const bool initialized) {
  if (initialized) {
    params->_initialized_fields[ATCLIENT_NOTIFY_PARAMS_OPERATION_INDEX] |= ATCLIENT_NOTIFY_PARAMS_OPERATION_INITIALIZED;
  } else {
    params->_initialized_fields[ATCLIENT_NOTIFY_PARAMS_OPERATION_INDEX] &=
        ~ATCLIENT_NOTIFY_PARAMS_OPERATION_INITIALIZED;
  }
}

void atclient_notify_params_set_message_type_initialized(atclient_notify_params *params, const bool initialized) {
  if (initialized) {
    params->_initialized_fields[ATCLIENT_NOTIFY_PARAMS_MESSAGE_TYPE_INDEX] |=
        ATCLIENT_NOTIFY_PARAMS_MESSAGE_TYPE_INITIALIZED;
  } else {
    params->_initialized_fields[ATCLIENT_NOTIFY_PARAMS_MESSAGE_TYPE_INDEX] &=
        ~ATCLIENT_NOTIFY_PARAMS_MESSAGE_TYPE_INITIALIZED;
  }
}

void atclient_notify_params_set_priority_initialized(atclient_notify_params *params, const bool initialized) {
  if (initialized) {
    params->_initialized_fields[ATCLIENT_NOTIFY_PARAMS_PRIORITY_INDEX] |= ATCLIENT_NOTIFY_PARAMS_PRIORITY_INITIALIZED;
  } else {
    params->_initialized_fields[ATCLIENT_NOTIFY_PARAMS_PRIORITY_INDEX] &= ~ATCLIENT_NOTIFY_PARAMS_PRIORITY_INITIALIZED;
  }
}

void atclient_notify_params_set_strategy_initialized(atclient_notify_params *params, const bool initialized) {
  if (initialized) {
    params->_initialized_fields[ATCLIENT_NOTIFY_PARAMS_STRATEGY_INDEX] |= ATCLIENT_NOTIFY_PARAMS_STRATEGY_INITIALIZED;
  } else {
    params->_initialized_fields[ATCLIENT_NOTIFY_PARAMS_STRATEGY_INDEX] &= ~ATCLIENT_NOTIFY_PARAMS_STRATEGY_INITIALIZED;
  }
}

void atclient_notify_params_set_latest_n_initialized(atclient_notify_params *params, const bool initialized) {
  if (initialized) {
    params->_initialized_fields[ATCLIENT_NOTIFY_PARAMS_LATEST_N_INDEX] |= ATCLIENT_NOTIFY_PARAMS_LATEST_N_INITIALIZED;
  } else {
    params->_initialized_fields[ATCLIENT_NOTIFY_PARAMS_LATEST_N_INDEX] &= ~ATCLIENT_NOTIFY_PARAMS_LATEST_N_INITIALIZED;
  }
}

void atclient_notify_params_set_notifier_initialized(atclient_notify_params *params, const bool initialized) {
  if (initialized) {
    params->_initialized_fields[ATCLIENT_NOTIFY_PARAMS_NOTIFIER_INDEX] |= ATCLIENT_NOTIFY_PARAMS_NOTIFIER_INITIALIZED;
  } else {
    params->_initialized_fields[ATCLIENT_NOTIFY_PARAMS_NOTIFIER_INDEX] &= ~ATCLIENT_NOTIFY_PARAMS_NOTIFIER_INITIALIZED;
  }
}

void atclient_notify_params_set_notification_expiry_initialized(atclient_notify_params *params,
                                                                const bool initialized) {
  if (initialized) {
    params->_initialized_fields[ATCLIENT_NOTIFY_PARAMS_NOTIFICATION_EXPIRY_INDEX] |=
        ATCLIENT_NOTIFY_PARAMS_NOTIFICATION_EXPIRY_INITIALIZED;
  } else {
    params->_initialized_fields[ATCLIENT_NOTIFY_PARAMS_NOTIFICATION_EXPIRY_INDEX] &=
        ~ATCLIENT_NOTIFY_PARAMS_NOTIFICATION_EXPIRY_INITIALIZED;
  }
}

void atclient_notify_params_set_shared_encryption_key_initialized(atclient_notify_params *params,
                                                                  const bool initialized) {
  if (initialized) {
    params->_initialized_fields[ATCLIENT_NOTIFY_PARAMS_SHARED_ENCRYPTION_KEY_INDEX] |=
        ATCLIENT_NOTIFY_PARAMS_SHARED_ENCRYPTION_KEY_INITIALIZED;
  } else {
    params->_initialized_fields[ATCLIENT_NOTIFY_PARAMS_SHARED_ENCRYPTION_KEY_INDEX] &=
        ~ATCLIENT_NOTIFY_PARAMS_SHARED_ENCRYPTION_KEY_INITIALIZED;
  }
}

int atclient_notify_params_set_id(atclient_notify_params *params, const char *id) {
  int ret = 1;

  if (atclient_notify_params_is_id_initialized(params)) {
    atclient_notify_params_unset_id(params);
  }

  const size_t id_len = strlen(id);
  const size_t id_size = id_len + 1;
  if ((params->id = (char *)malloc(sizeof(char) * id_size)) == NULL) {
    ret = 1;
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "Failed to allocate memory for id\n");
    goto exit;
  }

  memcpy(params->id, id, id_len);
  params->id[id_len] = '\0';

  ret = 0;
  goto exit;
exit: { return ret; }
}

int atclient_notify_params_set_atkey(atclient_notify_params *params, const atclient_atkey *atkey) {
  int ret = 1;
  if (atclient_notify_params_is_atkey_initialized(params)) {
    atclient_notify_params_unset_atkey(params);
  }

  if ((params->atkey = (atclient_atkey *)malloc(sizeof(atclient_atkey))) == NULL) {
    ret = 1;
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "Failed to allocate memory for atkey\n");
    goto exit;
  }

  atclient_atkey_init(params->atkey);
  if ((ret = atclient_atkey_clone(params->atkey, atkey)) != 0) {
    ret = 1;
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atclient_atkey_clone: %d\n", ret);
    goto exit;
  }
  atclient_notify_params_set_atkey_initialized(params, true);

  ret = 0;
  goto exit;
exit: { return ret; }
}

int atclient_notify_params_set_value(atclient_notify_params *params, const char *value) {
  int ret = 1;

  if (atclient_notify_params_is_value_initialized(params)) {
    atclient_notify_params_unset_value(params);
  }

  const size_t value_len = strlen(value);
  const size_t value_size = value_len + 1;
  if ((params->value = (char *)malloc(sizeof(char) * (value_size))) == NULL) {
    ret = 1;
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "Failed to allocate memory for value\n");
    goto exit;
  }
  memcpy(params->value, value, value_len);
  params->value[value_len] = '\0';

  atclient_notify_params_set_value_initialized(params, true);

  ret = 0;
  goto exit;
exit: { return ret; }
}

int atclient_notify_params_set_should_encrypt(atclient_notify_params *params, const bool should_encrypt) {
  params->should_encrypt = should_encrypt;
  atclient_notify_params_set_should_encrypt_initialized(params, true);
  return 0;
}

int atclient_notify_params_set_operation(atclient_notify_params *params,
                                         const enum atclient_notify_operation operation) {
  params->operation = operation;
  atclient_notify_params_set_operation_initialized(params, true);
  return 0;
}

int atclient_notify_params_set_message_type(atclient_notify_params *params,
                                            const enum atclient_notify_message_type message_type) {
  params->message_type = message_type;
  atclient_notify_params_set_message_type_initialized(params, true);
  return 0;
}

int atclient_notify_params_set_priority(atclient_notify_params *params, const enum atclient_notify_priority priority) {
  params->priority = priority;
  atclient_notify_params_set_priority_initialized(params, true);
  return 0;
}

int atclient_notify_params_set_strategy(atclient_notify_params *params, const enum atclient_notify_strategy strategy) {
  params->strategy = strategy;
  atclient_notify_params_set_strategy_initialized(params, true);
  return 0;
}

int atclient_notify_params_set_latest_n(atclient_notify_params *params, const int latest_n) {
  params->latest_n = latest_n;
  atclient_notify_params_set_latest_n_initialized(params, true);
  return 0;
}

int atclient_notify_params_set_notifier(atclient_notify_params *params, const char *notifier) {
  int ret = 1;

  if (atclient_notify_params_is_notifier_initialized(params)) {
    atclient_notify_params_unset_notifier(params);
  }

  const size_t notifier_len = strlen(notifier);
  const size_t notifier_size = notifier_len + 1;
  if ((params->notifier = (char *)malloc(sizeof(char) * (notifier_size))) == NULL) {
    ret = 1;
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "Failed to allocate memory for notifier\n");
    goto exit;
  }

  memcpy(params->notifier, notifier, notifier_len);
  params->notifier[notifier_len] = '\0';

  atclient_notify_params_set_notifier_initialized(params, true);

  ret = 0;
  goto exit;
exit: { return ret; }
}

int atclient_notify_params_set_notification_expiry(atclient_notify_params *params,
                                                   const unsigned long notification_expiry) {
  params->notification_expiry = notification_expiry;
  atclient_notify_params_set_notification_expiry_initialized(params, true);
  return 0;
}

int atclient_notify_params_set_shared_encryption_key(atclient_notify_params *params,
                                                     const unsigned char *shared_encryption_key) {
  int ret = 1;

  if (atclient_notify_params_is_shared_encryption_key_initialized(params)) {
    atclient_notify_params_unset_shared_encryption_key(params);
  }

  const size_t shared_encryption_key_size = ATCHOPS_AES_256 / 8;

  if ((params->shared_encryption_key = (unsigned char *)malloc(sizeof(unsigned char) * shared_encryption_key_size)) ==
      NULL) {
    ret = 1;
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "Failed to allocate memory for shared_encryption_key\n");
    goto exit;
  }
  memcpy(params->shared_encryption_key, shared_encryption_key, shared_encryption_key_size);

  atclient_notify_params_set_shared_encryption_key_initialized(params, true);

  ret = 0;
  goto exit;
exit: { return ret; }
}

void atclient_notify_params_unset_id(atclient_notify_params *params) {
  if (atclient_notify_params_is_id_initialized(params)) {
    free(params->id);
  }
  params->id = NULL;
  atclient_notify_params_set_id_initialized(params, false);
}

void atclient_notify_params_unset_atkey(atclient_notify_params *params) {
  if (atclient_notify_params_is_atkey_initialized(params)) {
    atclient_atkey_free(params->atkey);
    free(params->atkey);
  }
  params->atkey = NULL;
  atclient_notify_params_set_atkey_initialized(params, false);
}

void atclient_notify_params_unset_value(atclient_notify_params *params) {
  if (atclient_notify_params_is_value_initialized(params)) {
    free(params->value);
  }
  params->value = NULL;
  atclient_notify_params_set_value_initialized(params, false);
}

void atclient_notify_params_unset_should_encrypt(atclient_notify_params *params) {
  params->should_encrypt = true;
  atclient_notify_params_set_should_encrypt_initialized(params, false);
}

void atclient_notify_params_unset_operation(atclient_notify_params *params) {
  params->operation = ATCLIENT_NOTIFY_OPERATION_NONE;
  atclient_notify_params_set_operation_initialized(params, false);
}

void atclient_notify_params_unset_message_type(atclient_notify_params *params) {
  params->message_type = ATCLIENT_NOTIFY_MESSAGE_TYPE_KEY;
  atclient_notify_params_set_message_type_initialized(params, false);
}

void atclient_notify_params_unset_priority(atclient_notify_params *params) {
  params->priority = ATCLIENT_NOTIFY_PRIORITY_LOW;
  atclient_notify_params_set_priority_initialized(params, false);
}

void atclient_notify_params_unset_strategy(atclient_notify_params *params) {
  params->strategy = ATCLIENT_NOTIFY_STRATEGY_ALL;
  atclient_notify_params_set_strategy_initialized(params, false);
}

void atclient_notify_params_unset_latest_n(atclient_notify_params *params) {
  params->latest_n = 1;
  atclient_notify_params_set_latest_n_initialized(params, false);
}

void atclient_notify_params_unset_notifier(atclient_notify_params *params) {
  if (atclient_notify_params_is_notifier_initialized(params)) {
    free(params->notifier);
  }
  params->notifier = ATCLIENT_DEFAULT_NOTIFIER;
  atclient_notify_params_set_notifier_initialized(params, false);
}

void atclient_notify_params_unset_notification_expiry(atclient_notify_params *params) {
  params->notification_expiry = 24 * 60 * 60 * 1000;
  atclient_notify_params_set_notification_expiry_initialized(params, false);
}

void atclient_notify_params_unset_shared_encryption_key(atclient_notify_params *params) {
  if (atclient_notify_params_is_shared_encryption_key_initialized(params)) {
    free(params->shared_encryption_key);
  }
  params->shared_encryption_key = NULL;
  atclient_notify_params_set_shared_encryption_key_initialized(params, false);
}
