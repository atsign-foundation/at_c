#ifndef ATCLIENT_NOTIFY_PARAMS_H
#define ATCLIENT_NOTIFY_PARAMS_H

#include "atclient/atclient.h"
#include "atclient/atkey.h"

#define VALUE_INITIALIZED 0b00000001

#define ATCLIENT_NOTIFY_PARAMS_ID_INDEX 0
#define ATCLIENT_NOTIFY_PARAMS_ATKEY_INDEX 0
#define ATCLIENT_NOTIFY_PARAMS_VALUE_INDEX 0
#define ATCLIENT_NOTIFY_PARAMS_SHOULD_ENCRYPT_INDEX 0
#define ATCLIENT_NOTIFY_PARAMS_OPERATION_INDEX 0
#define ATCLIENT_NOTIFY_PARAMS_MESSAGE_TYPE_INDEX 0
#define ATCLIENT_NOTIFY_PARAMS_PRIORITY_INDEX 0
#define ATCLIENT_NOTIFY_PARAMS_STRATEGY_INDEX 0

#define ATCLIENT_NOTIFY_PARAMS_LATEST_N_INDEX 1
#define ATCLIENT_NOTIFY_PARAMS_NOTIFIER_INDEX 1
#define ATCLIENT_NOTIFY_PARAMS_NOTIFICATION_EXPIRY_INDEX 1
#define ATCLIENT_NOTIFY_PARAMS_SHARED_ENCRYPTION_KEY_INDEX 1

#define ATCLIENT_NOTIFY_PARAMS_ID_INITIALIZED (VALUE_INITIALIZED << 0)
#define ATCLIENT_NOTIFY_PARAMS_ATKEY_INITIALIZED (VALUE_INITIALIZED << 1)
#define ATCLIENT_NOTIFY_PARAMS_VALUE_INITIALIZED (VALUE_INITIALIZED << 2)
#define ATCLIENT_NOTIFY_PARAMS_SHOULD_ENCRYPT_INITIALIZED (VALUE_INITIALIZED << 3)
#define ATCLIENT_NOTIFY_PARAMS_OPERATION_INITIALIZED (VALUE_INITIALIZED << 4)
#define ATCLIENT_NOTIFY_PARAMS_MESSAGE_TYPE_INITIALIZED (VALUE_INITIALIZED << 5)
#define ATCLIENT_NOTIFY_PARAMS_PRIORITY_INITIALIZED (VALUE_INITIALIZED << 6)
#define ATCLIENT_NOTIFY_PARAMS_STRATEGY_INITIALIZED (VALUE_INITIALIZED << 7)

#define ATCLIENT_NOTIFY_PARAMS_LATEST_N_INITIALIZED (VALUE_INITIALIZED << 0)
#define ATCLIENT_NOTIFY_PARAMS_NOTIFIER_INITIALIZED (VALUE_INITIALIZED << 1)
#define ATCLIENT_NOTIFY_PARAMS_NOTIFICATION_EXPIRY_INITIALIZED (VALUE_INITIALIZED << 2)
#define ATCLIENT_NOTIFY_PARAMS_SHARED_ENCRYPTION_KEY_INITIALIZED (VALUE_INITIALIZED << 3)

enum atclient_notify_operation {
  ATCLIENT_NOTIFY_OPERATION_NONE,
  ATCLIENT_NOTIFY_OPERATION_UPDATE,
  ATCLIENT_NOTIFY_OPERATION_DELETE
};

static const char *atclient_notify_operation_str[] = {
    [ATCLIENT_NOTIFY_OPERATION_UPDATE] = "update",
    [ATCLIENT_NOTIFY_OPERATION_DELETE] = "delete",
};

enum atclient_notify_message_type {
  ATCLIENT_NOTIFY_MESSAGE_TYPE_NONE,
  ATCLIENT_NOTIFY_MESSAGE_TYPE_KEY,
  ATCLIENT_NOTIFY_MESSAGE_TYPE_TEXT
};

static const char *atclient_notify_message_type_str[] = {
    [ATCLIENT_NOTIFY_MESSAGE_TYPE_KEY] = "key",
    [ATCLIENT_NOTIFY_MESSAGE_TYPE_TEXT] = "text", // legacy
};

enum atclient_notify_priority {
  ATCLIENT_NOTIFY_PRIORITY_NONE,
  ATCLIENT_NOTIFY_PRIORITY_LOW,
  ATCLIENT_NOTIFY_PRIORITY_MEDIUM,
  ATCLIENT_NOTIFY_PRIORITY_HIGH
};

static const char *atclient_notify_priority_str[] = {
    [ATCLIENT_NOTIFY_PRIORITY_LOW] = "low",
    [ATCLIENT_NOTIFY_PRIORITY_MEDIUM] = "medium",
    [ATCLIENT_NOTIFY_PRIORITY_HIGH] = "high",
};

enum atclient_notify_strategy {
  ATCLIENT_NOTIFY_STRATEGY_NONE,
  ATCLIENT_NOTIFY_STRATEGY_ALL,
  ATCLIENT_NOTIFY_STRATEGY_LATEST
};

static const char *atclient_notify_strategy_str[] = {
    [ATCLIENT_NOTIFY_STRATEGY_ALL] = "all",
    [ATCLIENT_NOTIFY_STRATEGY_LATEST] = "latest",
};

typedef struct atclient_notify_params {
  char *id;
  atclient_atkey *atkey;
  char *value;
  bool should_encrypt;
  enum atclient_notify_operation operation;
  enum atclient_notify_message_type message_type;
  enum atclient_notify_priority priority;
  enum atclient_notify_strategy strategy;
  int latest_n;
  char *notifier;
  unsigned long notification_expiry;
  unsigned char *shared_encryption_key;

  uint8_t _initializedfields[2];
} atclient_notify_params;

void atclient_notify_params_init(atclient_notify_params *params);
void atclient_notify_params_free(atclient_notify_params *params);

bool atclient_notify_params_is_id_initialized(atclient_notify_params *params);
bool atclient_notify_params_is_atkey_initialized(atclient_notify_params *params);
bool atclient_notify_params_is_value_initialized(atclient_notify_params *params);
bool atclient_notify_params_is_shouldencrypt_initialized(atclient_notify_params *params);
bool atclient_notify_params_is_operation_initialized(atclient_notify_params *params);
bool atclient_notify_params_is_message_type_initialized(atclient_notify_params *params);
bool atclient_notify_params_is_priority_initialized(atclient_notify_params *params);
bool atclient_notify_params_is_strategy_initialized(atclient_notify_params *params);
bool atclient_notify_params_is_latest_n_initialized(atclient_notify_params *params);
bool atclient_notify_params_is_notifier_initialized(atclient_notify_params *params);
bool atclient_notify_params_is_notification_expiry_initialized(atclient_notify_params *params);
bool atclient_notify_params_is_shared_encryption_key_initialized(atclient_notify_params *params);

void atclient_notify_params_set_id_initialized(atclient_notify_params *params, const bool initialized);
void atclient_notify_params_set_atkey_initialized(atclient_notify_params *params, const bool initialized);
void atclient_notify_params_set_value_initialized(atclient_notify_params *params, const bool initialized);
void atclient_notify_params_set_shouldencrypt_initialized(atclient_notify_params *params, const bool initialized);
void atclient_notify_params_set_operation_initialized(atclient_notify_params *params, const bool initialized);
void atclient_notify_params_set_message_type_initialized(atclient_notify_params *params, const bool initialized);
void atclient_notify_params_set_priority_initialized(atclient_notify_params *params, const bool initialized);
void atclient_notify_params_set_strategy_initialized(atclient_notify_params *params, const bool initialized);
void atclient_notify_params_set_latest_n_initialized(atclient_notify_params *params, const bool initialized);
void atclient_notify_params_set_notifier_initialized(atclient_notify_params *params, const bool initialized);
void atclient_notify_params_set_notification_expiry_initialized(atclient_notify_params *params, const bool initialized);
void atclient_notify_params_set_shared_encryption_key_initialized(atclient_notify_params *params, const bool initialized);

int atclient_notify_params_set_id(atclient_notify_params *params, const char *id, const size_t id_len);
int atclient_notify_params_set_atkey(atclient_notify_params *params, const atclient_atkey *atkey);
int atclient_notify_params_set_value(atclient_notify_params *params, const char *value, const size_t value_len);
int atclient_notify_params_set_should_encrypt(atclient_notify_params *params, const bool should_encrypt);
int atclient_notify_params_set_operation(atclient_notify_params *params, const enum atclient_notify_operation operation);
int atclient_notify_params_set_message_type(atclient_notify_params *params, const enum atclient_notify_message_type message_type);
int atclient_notify_params_set_priority(atclient_notify_params *params, const enum atclient_notify_priority priority);
int atclient_notify_params_set_strategy(atclient_notify_params *params, const enum atclient_notify_strategy strategy);
int atclient_notify_params_set_latest_n(atclient_notify_params *params, const int latest_n);
int atclient_notify_params_set_notifier(atclient_notify_params *params, const char *notifier, const size_t notifier_len);
int atclient_notify_params_set_notification_expiry(atclient_notify_params *params, const unsigned long notification_expiry);
int atclient_notify_params_set_shared_encryption_key(atclient_notify_params *params, const unsigned char *shared_encryption_key, const size_t shared_encryption_key_len);

void atclient_notify_params_unset_id(atclient_notify_params *params);
void atclient_notify_params_unset_atkey(atclient_notify_params *params);
void atclient_notify_params_unset_value(atclient_notify_params *params);
void atclient_notify_params_unset_should_encrypt(atclient_notify_params *params);
void atclient_notify_params_unset_operation(atclient_notify_params *params);
void atclient_notify_params_unset_message_type(atclient_notify_params *params);
void atclient_notify_params_unset_priority(atclient_notify_params *params);
void atclient_notify_params_unset_strategy(atclient_notify_params *params);
void atclient_notify_params_unset_latest_n(atclient_notify_params *params);
void atclient_notify_params_unset_notifier(atclient_notify_params *params);
void atclient_notify_params_unset_notification_expiry(atclient_notify_params *params);
void atclient_notify_params_unset_shared_encryption_key(atclient_notify_params *params);

#endif // ATCLIENT_NOTIFY_PARAMS_H
