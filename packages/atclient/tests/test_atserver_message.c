#include "atlogger/atlogger.h"
#include "atserver_message.h"
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define BASE_TAG(X) "test_atserver_message " X

// non-heap tests
static uint8_t test_1a_long_prompt();
static uint8_t test_1b_short_prompt();
static uint8_t test_1c_no_prompt();
static uint8_t test_2a_no_token();
static uint8_t test_3a_no_body();
static uint8_t test_4a_empty_message();

// heap tests
static uint8_t test_5a_heap();
static uint8_t test_5b_bad_parse_heap();

int main() {
  int ret = 0;
  atlogger_set_logging_level(ATLOGGER_LOGGING_LEVEL_INFO);

  ret += test_1a_long_prompt();
  ret += test_1b_short_prompt();
  ret += test_1c_no_prompt();
  ret += test_2a_no_token();
  ret += test_3a_no_body();
  ret += test_4a_empty_message();
  ret += test_5a_heap();
  ret += test_5b_bad_parse_heap();

  if (ret > 0) {
    atlogger_log("test_atserver_message", ATLOGGER_LOGGING_LEVEL_ERROR, "%d tests failed\n", ret);
  }
  return ret;
}

#define expect_uint(TEST_TAG, EXP, ACT)                                                                                \
  if (EXP != ACT) {                                                                                                    \
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "%s: incorrect value (expected: %u, actual: %u)\n", TEST_TAG, EXP, \
                 ACT);                                                                                                 \
    return 1;                                                                                                          \
  }

uint8_t test_1a_long_prompt() {
  const char *TAG = BASE_TAG("1a");
  char *buffer = "@foobar@data:baz";
  const uint16_t len = strlen(buffer);

  struct atserver_message message = atserver_message_parse(buffer, len);

  if (message.buffer == NULL) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "message.buffer is NULL\n");
    return 1;
  }

  expect_uint("prompt len", 8, message.prompt_len);
  expect_uint("token len", 5, message.token_len);
  expect_uint("body len", 3, atserver_message_get_body_len(message));
  expect_uint("len", 16, message.len);

  return 0;
}

uint8_t test_1b_short_prompt() {
  const char *TAG = BASE_TAG("1b");
  char *buffer = "@data:baz";
  const uint16_t len = strlen(buffer);

  struct atserver_message message = atserver_message_parse(buffer, len);

  if (message.buffer == NULL) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "message.buffer is NULL\n");
    return 1;
  }

  expect_uint("prompt len", 1, message.prompt_len);
  expect_uint("token len", 5, message.token_len);
  expect_uint("body len", 3, atserver_message_get_body_len(message));
  expect_uint("len", 9, message.len);

  return 0;
}

uint8_t test_1c_no_prompt() {
  const char *TAG = BASE_TAG("1c");
  char *buffer = "data:baz";
  const uint16_t len = strlen(buffer);

  struct atserver_message message = atserver_message_parse(buffer, len);

  if (message.buffer == NULL) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "message.buffer is NULL\n");
    return 1;
  }

  expect_uint("prompt len", 0, message.prompt_len);
  expect_uint("token len", 5, message.token_len);
  expect_uint("body len", 3, atserver_message_get_body_len(message));
  expect_uint("len", 8, message.len);

  return 0;
}

uint8_t test_2a_no_token() {
  const char *TAG = BASE_TAG("2a");
  char *buffer = "@foo@baz";
  const uint16_t len = strlen(buffer);

  struct atserver_message message = atserver_message_parse(buffer, len);

  if (message.buffer != NULL) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "message.buffer is expected to be NULL but it isn't\n");
    return 1;
  }

  expect_uint("prompt len", 0, message.prompt_len);
  expect_uint("token len", 0, message.token_len);
  expect_uint("body len", 0, atserver_message_get_body_len(message));
  expect_uint("len", 0, message.len);

  return 0;
}

uint8_t test_3a_no_body() {
  const char *TAG = BASE_TAG("3a");
  char *buffer = "@foobar@data:";
  const uint16_t len = strlen(buffer);

  struct atserver_message message = atserver_message_parse(buffer, len);

  if (message.buffer == NULL) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "message.buffer is NULL\n");
    return 1;
  }

  expect_uint("prompt len", 8, message.prompt_len);
  expect_uint("token len", 5, message.token_len);
  expect_uint("body len", 0, atserver_message_get_body_len(message));
  expect_uint("len", 13, message.len);

  return 0;
}

uint8_t test_4a_empty_message() {
  const char *TAG = BASE_TAG("4a");
  char *buffer = "";
  const uint16_t len = strlen(buffer);

  struct atserver_message message = atserver_message_parse(buffer, len);

  if (message.buffer != NULL) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "message.buffer is expected to be NULL but it isn't\n");
    return 1;
  }

  expect_uint("prompt len", 0, message.prompt_len);
  expect_uint("token len", 0, message.token_len);
  expect_uint("body len", 0, atserver_message_get_body_len(message));
  expect_uint("len", 0, message.len);

  return 0;
}

uint8_t test_5a_heap() {
  const char *TAG = BASE_TAG("5a");
  char *static_buffer = "@foobar@data:baz";
  const uint16_t len = strlen(static_buffer);
  char *heap_buffer = malloc(sizeof(char) * len);
  if (heap_buffer == NULL) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "Failed to allocate heap buffer for test\n");
    return 1;
  }
  memcpy(heap_buffer, static_buffer, sizeof(char) * len);

  struct atserver_message message = atserver_message_parse(heap_buffer, len);

  if (message.buffer == NULL) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "message.buffer is NULL\n");
    free(heap_buffer);
    return 1;
  }

  expect_uint("prompt len", 8, message.prompt_len);
  expect_uint("token len", 5, message.token_len);
  expect_uint("body len", 3, atserver_message_get_body_len(message));
  expect_uint("len", 16, message.len);

  message.buffer[0] = 'H';
  if (strncmp(heap_buffer, "Hfoobar@data:baz", len) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "message.buffer is not the original heap buffer\n");
    free(heap_buffer);
    return 1;
  }

  atserver_message_free(&message);
  if (message.buffer != NULL) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR,
                 "message.buffer is expected to be NULL after free but it isn't: %zu\n", message.buffer);
    return 1;
  }

  atserver_message_free(&message); // call again to ensure resilience against double free

  return 0;
}

uint8_t test_5b_bad_parse_heap() {
  const char *TAG = BASE_TAG("5b");
  char *static_buffer = "@foobar@baz";
  const uint16_t len = strlen(static_buffer);
  char *heap_buffer = malloc(sizeof(char) * len);
  if (heap_buffer == NULL) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "Failed to allocate heap buffer for test\n");
    return 1;
  }
  memcpy(heap_buffer, static_buffer, sizeof(char) * len);

  struct atserver_message message = atserver_message_parse(heap_buffer, len);

  if (message.buffer != NULL) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "message.buffer is expected to be NULL but it isn't\n");
    free(heap_buffer);
    return 1;
  }

  expect_uint("prompt len", 0, message.prompt_len);
  expect_uint("token len", 0, message.token_len);
  expect_uint("body len", 0, atserver_message_get_body_len(message));
  expect_uint("len", 0, message.len);

  // ensure original heap buffer is intact
  if (strncmp(heap_buffer, static_buffer, len) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "heap_buffer is malformed after a failed parse\n");
    free(heap_buffer);
    return 1;
  }

  free(heap_buffer);

  return 0;
}
