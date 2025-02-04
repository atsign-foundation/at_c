#include "atclient/monitor.h"
#include "atlogger/atlogger.h"
#include "atserver_message.h"
#include "monitor.h"
#include <stdio.h>
#include <string.h>

#define TAG "test_parse_monitor"

// data
static int test_1a_populate_data_ok();
static int test_1b_populate_data_empty();

// error
static int test_2a_populate_error_msg();
static int test_2b_populate_error_empty();

// notification
static int test_3a_populate_notification_msg();
static int test_3b_populate_notification_empty();
static int test_3c_populate_notification_invalid_json();

int main() {
  int ret = 0;
  atlogger_set_logging_level(ATLOGGER_LOGGING_LEVEL_INFO);

  ret += test_1a_populate_data_ok();
  ret += test_1b_populate_data_empty();
  ret += test_2a_populate_error_msg();
  ret += test_2b_populate_error_empty();
  ret += test_3a_populate_notification_msg();
  ret += test_3b_populate_notification_empty();
  ret += test_3c_populate_notification_invalid_json();

  if (ret > 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "%d tests failed\n", ret);
  }
  return ret;
}

static int test_1a_populate_data_ok() {
  const char *input = "@bob@data:foo";
  size_t input_len = strlen(input);
  char *buffer = malloc(sizeof(char) * (input_len + 1));
  memcpy(buffer, input, strlen(input));
  buffer[input_len] = 0;

  struct atserver_message *message = malloc(sizeof(struct atserver_message));
  struct atserver_message temp_message = atserver_message_parse(buffer, strlen(buffer));
  memcpy(message, &temp_message, sizeof(struct atserver_message));
  atclient_monitor_message monitor_message;
  atclient_monitor_message_init(&monitor_message);
  monitor_message.atserver_message = message;
  int ret = populate_monitor_message(&monitor_message);
  if (monitor_message.type != ATCLIENT_MONITOR_MESSAGE_TYPE_DATA_RESPONSE) {
    atlogger_log(TAG " 1a", ATLOGGER_LOGGING_LEVEL_ERROR, "Expected data response type\n");
    atclient_monitor_message_free(&monitor_message);
    return 1;
  }
  if (ret != 0) {
    atlogger_log(TAG " 1a", ATLOGGER_LOGGING_LEVEL_ERROR, "Failed to populate monitor message\n");
    atclient_monitor_message_free(&monitor_message);
    return 1;
  }
  if (monitor_message.data_response == NULL) {
    atlogger_log(TAG " 1a", ATLOGGER_LOGGING_LEVEL_ERROR, "monitor_message.data_response is NULL\n");
    atclient_monitor_message_free(&monitor_message);
    return 1;
  }
  if (strlen(monitor_message.data_response) != 3 || strncmp(monitor_message.data_response, "foo", 3) != 0) {
    atlogger_log(TAG " 1a", ATLOGGER_LOGGING_LEVEL_ERROR,
                 "Did not receive expected monitor message data response: %s\n", monitor_message.data_response);
    atclient_monitor_message_free(&monitor_message);
    return 1;
  }
  atclient_monitor_message_free(&monitor_message);
  return 0;
}

static int test_1b_populate_data_empty() {
  char *input = "@bob@data:";
  size_t input_len = strlen(input);
  char *buffer = malloc(sizeof(char) * (input_len + 1));
  memcpy(buffer, input, strlen(input));
  buffer[input_len] = 0;

  struct atserver_message *message = malloc(sizeof(struct atserver_message));
  struct atserver_message temp_message = atserver_message_parse(buffer, strlen(buffer));
  memcpy(message, &temp_message, sizeof(struct atserver_message));
  atclient_monitor_message monitor_message;
  atclient_monitor_message_init(&monitor_message);
  monitor_message.atserver_message = message;
  int ret = populate_monitor_message(&monitor_message);
  if (ret == 0) {
    atclient_monitor_message_free(&monitor_message);
    atlogger_log(TAG " 1b", ATLOGGER_LOGGING_LEVEL_ERROR, "Expected populate_monitor_message to fail\n");
    return 1;
  }
  if (monitor_message.type != ATCLIENT_MONITOR_MESSAGE_TYPE_DATA_RESPONSE) {
    atlogger_log(TAG " 1b", ATLOGGER_LOGGING_LEVEL_ERROR, "Expected data response type\n");
    atclient_monitor_message_free(&monitor_message);
    return 1;
  }
  atclient_monitor_message_free(&monitor_message);
  return 0;
}

static int test_2a_populate_error_msg() {
  char *input = "@bob@error:bar";
  size_t input_len = strlen(input);
  char *buffer = malloc(sizeof(char) * (input_len + 1));
  memcpy(buffer, input, strlen(input));
  buffer[input_len] = 0;

  struct atserver_message *message = malloc(sizeof(struct atserver_message));
  struct atserver_message temp_message = atserver_message_parse(buffer, strlen(buffer));
  memcpy(message, &temp_message, sizeof(struct atserver_message));
  atclient_monitor_message monitor_message;
  atclient_monitor_message_init(&monitor_message);
  monitor_message.atserver_message = message;
  int ret = populate_monitor_message(&monitor_message);
  if (ret != 0) {
    atlogger_log(TAG " 2a", ATLOGGER_LOGGING_LEVEL_ERROR, "Failed to populate monitor message\n");
    atclient_monitor_message_free(&monitor_message);
    return 1;
  }
  if (monitor_message.type != ATCLIENT_MONITOR_MESSAGE_TYPE_ERROR_RESPONSE) {
    atlogger_log(TAG " 2a", ATLOGGER_LOGGING_LEVEL_ERROR, "Expected error response type\n");
    atclient_monitor_message_free(&monitor_message);
    return 1;
  }
  if (monitor_message.error_response == NULL) {
    atlogger_log(TAG " 2a", ATLOGGER_LOGGING_LEVEL_ERROR, "monitor_message.error_response is NULL\n");
    atclient_monitor_message_free(&monitor_message);
    return 1;
  }
  if (strlen(monitor_message.error_response) != 3 || strncmp(monitor_message.error_response, "bar", 3) != 0) {
    atlogger_log(TAG " 2a", ATLOGGER_LOGGING_LEVEL_ERROR,
                 "Did not receive expected monitor message data response: %s\n", monitor_message.error_response);
    atclient_monitor_message_free(&monitor_message);
    return 1;
  }
  atclient_monitor_message_free(&monitor_message);
  return 0;
}

static int test_2b_populate_error_empty() {
  char *input = "@bob@error:";
  size_t input_len = strlen(input);
  char *buffer = malloc(sizeof(char) * (input_len + 1));
  memcpy(buffer, input, strlen(input));
  buffer[input_len] = 0;

  struct atserver_message *message = malloc(sizeof(struct atserver_message));
  struct atserver_message temp_message = atserver_message_parse(buffer, strlen(buffer));
  memcpy(message, &temp_message, sizeof(struct atserver_message));
  atclient_monitor_message monitor_message;
  atclient_monitor_message_init(&monitor_message);
  monitor_message.atserver_message = message;
  int ret = populate_monitor_message(&monitor_message);
  if (ret == 0) {
    atclient_monitor_message_free(&monitor_message);
    atlogger_log(TAG " 2b", ATLOGGER_LOGGING_LEVEL_ERROR, "Expected populate_monitor_message to fail\n");
    return 1;
  }
  if (monitor_message.type != ATCLIENT_MONITOR_MESSAGE_TYPE_ERROR_RESPONSE) {
    atlogger_log(TAG " 2b", ATLOGGER_LOGGING_LEVEL_ERROR, "Expected error response type\n");
    atclient_monitor_message_free(&monitor_message);
    return 1;
  }
  atclient_monitor_message_free(&monitor_message);
  return 0;
}

// {"id":"asdf","from":"@snooker25","to":"@52monkey","key":"@52monkey:foo@snooker25","value":"asdf","operation":"update","epochMillis":1738703592148,"messageType":"MessageType.key","isEncrypted":false,"metadata":{"encKeyName":null,"encAlgo":null,"ivNonce":null,"skeEncKeyName":null,"skeEncAlgo":null,"sharedKeyEnc":null,"pubKeyHash":null}}

// encrypted notification will be tested by functional tests
static int test_3a_populate_notification_msg() {
#define id3a "773e226d-dac2-4269-b1ee-64d7ce93a42f"
#define val3a "foobarbaz"
  char *input = "@bob@notification: {"
                "\"id\":\"" id3a "\","
                "\"from\":\"@alice\","
                "\"to\":\"@bob\","
                "\"key\":\"@bob:phone:@alice\","
                "\"value\":\"" val3a "\","
                "\"operation\":\"update\","
                "\"messageType\":\"MessageType.key\","
                "\"isEncrypted\":false"
                "}";
  size_t input_len = strlen(input);
  char *buffer = malloc(sizeof(char) * (input_len + 1));
  memcpy(buffer, input, strlen(input));
  buffer[input_len] = 0;

  struct atserver_message *message = malloc(sizeof(struct atserver_message));
  struct atserver_message temp_message = atserver_message_parse(buffer, strlen(buffer));
  memcpy(message, &temp_message, sizeof(struct atserver_message));
  atclient_monitor_message monitor_message;
  atclient_monitor_message_init(&monitor_message);
  monitor_message.atserver_message = message;
  int ret = populate_monitor_message(&monitor_message);

  if (ret != 0) {
    atclient_monitor_message_free(&monitor_message);
    atlogger_log(TAG " 3a", ATLOGGER_LOGGING_LEVEL_ERROR, "populate_monitor_message failed\n");
    return 1;
  }

  if (monitor_message.type != ATCLIENT_MONITOR_MESSAGE_TYPE_NOTIFICATION) {
    atlogger_log(TAG " 3a", ATLOGGER_LOGGING_LEVEL_ERROR, "Expected notification message type\n");
    atclient_monitor_message_free(&monitor_message);
    return 1;
  }

  // check id
  if (strlen(monitor_message.notification->id) != strlen(id3a) ||
      strncmp(monitor_message.notification->id, id3a, strlen(id3a)) != 0) {
    atlogger_log(TAG " 3a", ATLOGGER_LOGGING_LEVEL_ERROR,
                 "notification id did not match input:\n"
                 "\t\texpected len: %zu\n"
                 "\t\tactual len: %zu\n"
                 "\t\texpected value: %s\n"
                 "\t\tactual value: %s\n",
                 strlen(id3a), strlen(monitor_message.notification->id), id3a, monitor_message.notification->id);
    atclient_monitor_message_free(&monitor_message);
    return 1;
  }
  // check value
  if (strlen(monitor_message.notification->value) != strlen(val3a) ||
      strncmp(monitor_message.notification->value, val3a, strlen(val3a)) != 0) {
    atlogger_log(TAG " 3a", ATLOGGER_LOGGING_LEVEL_ERROR,
                 "notification value did not match input:\n"
                 "\t\texpected len: %zu\n"
                 "\t\tactual len: %zu\n"
                 "\t\texpected value: %s\n"
                 "\t\tactual value: %s\n",
                 strlen(val3a), strlen(monitor_message.notification->value), val3a, monitor_message.notification->id);
    atclient_monitor_message_free(&monitor_message);
    return 1;
  }
  atclient_monitor_message_free(&monitor_message);
  return 0;
}

static int test_3b_populate_notification_empty() {
  char *input = "@bob@notification:";
  size_t input_len = strlen(input);
  char *buffer = malloc(sizeof(char) * (input_len + 1));
  memcpy(buffer, input, strlen(input));
  buffer[input_len] = 0;

  struct atserver_message *message = malloc(sizeof(struct atserver_message));
  struct atserver_message temp_message = atserver_message_parse(buffer, strlen(buffer));
  memcpy(message, &temp_message, sizeof(struct atserver_message));
  atclient_monitor_message monitor_message;
  atclient_monitor_message_init(&monitor_message);
  monitor_message.atserver_message = message;
  int ret = populate_monitor_message(&monitor_message);
  if (ret == 0) {
    atclient_monitor_message_free(&monitor_message);
    atlogger_log(TAG " 3b", ATLOGGER_LOGGING_LEVEL_ERROR, "Expected populate_monitor_message to fail\n");
    return 1;
  }
  if (monitor_message.type != ATCLIENT_MONITOR_ERROR_PARSE_NOTIFICATION) {
    atlogger_log(TAG " 3b", ATLOGGER_LOGGING_LEVEL_ERROR, "Expected parse notification error type\n");
    atclient_monitor_message_free(&monitor_message);
    return 1;
  }
  atclient_monitor_message_free(&monitor_message);
  return 0;
}

static int test_3c_populate_notification_invalid_json() {
  char *input = "@bob@notification:{asdfasdfasdfasd";
  size_t input_len = strlen(input);
  char *buffer = malloc(sizeof(char) * (input_len + 1));
  memcpy(buffer, input, strlen(input));
  buffer[input_len] = 0;

  struct atserver_message *message = malloc(sizeof(struct atserver_message));
  struct atserver_message temp_message = atserver_message_parse(buffer, strlen(buffer));
  memcpy(message, &temp_message, sizeof(struct atserver_message));
  atclient_monitor_message monitor_message;
  atclient_monitor_message_init(&monitor_message);
  monitor_message.atserver_message = message;
  int ret = populate_monitor_message(&monitor_message);
  if (ret == 0) {
    atclient_monitor_message_free(&monitor_message);
    atlogger_log(TAG " 3c", ATLOGGER_LOGGING_LEVEL_ERROR, "Expected populate_monitor_message to fail\n");
    return 1;
  }
  if (monitor_message.type != ATCLIENT_MONITOR_ERROR_PARSE_NOTIFICATION) {
    atlogger_log(TAG " 3c", ATLOGGER_LOGGING_LEVEL_ERROR, "Expected parse notification error type\n");
    atclient_monitor_message_free(&monitor_message);
    return 1;
  }
  atclient_monitor_message_free(&monitor_message);
  return 0;
}
