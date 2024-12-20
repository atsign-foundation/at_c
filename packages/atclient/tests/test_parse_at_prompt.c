#include "atlogger/atlogger.h"
#include <atclient/atclient_utils.h>
#include <stdio.h>
#include <string.h>

#define TAG "test_parse_at_prompt"
static int test_1_atdirectory();
static int test_2_raw_atdirectory();
static int test_3_raw_notification();
static int test_4_prompt_notification();
static int test_5_data_response();
static int test_6_raw_data_response();
static int test_7_authed_data_response();
static int test_8_data_response();
static int test_9_raw_data_response();
static int test_10_authed_data_response();
static int test_11_null_atdirectory();

int main() {
  int ret = 0;
  atlogger_set_logging_level(ATLOGGER_LOGGING_LEVEL_INFO);

  ret += test_1_atdirectory();
  ret += test_2_raw_atdirectory();
  ret += test_3_raw_notification();
  ret += test_4_prompt_notification();
  ret += test_5_data_response();
  ret += test_6_raw_data_response();
  ret += test_7_authed_data_response();
  ret += test_8_data_response();
  ret += test_9_raw_data_response();
  ret += test_10_authed_data_response();
  ret += test_11_null_atdirectory();

  if (ret > 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "%d tests failed\n", ret);
  }
  return ret;
}

// returns 1 if EXP != ACT and logs the error
#define expect_size_t(TEST_TAG, EXP, ACT)                                                                              \
  if (EXP != ACT) {                                                                                                    \
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "%s: wrong idx value (expected: %d, actual: %d)\n", TEST_TAG, EXP, \
                 ACT);                                                                                                 \
    return 1;                                                                                                          \
  }

#define test_1_buffer "@190de331-8c62-42af-a549-6d3cd449fd16.swarm0001.atsign.zone:1234"
#define test_1_length strlen(test_1_buffer)
int test_1_atdirectory() {
  size_t idx;
  int ret = atclient_utils_find_index_past_at_prompt((unsigned char *)test_1_buffer, test_1_length, &idx);
  if (ret != 0) {
    return 1;
  }
  expect_size_t("test 1", 1, idx);

  return 0;
}

#define test_2_buffer "190de331-8c62-42af-a549-6d3cd449fd16.swarm0001.atsign.zone:1234"
#define test_2_length strlen(test_2_buffer)
int test_2_raw_atdirectory() {
  size_t idx;
  int ret = atclient_utils_find_index_past_at_prompt((unsigned char *)test_2_buffer, test_2_length, &idx);
  if (ret != 0) {
    return 1;
  }

  expect_size_t("test 2", 0, idx);

  return 0;
}

#define test_3_buffer                                                                                                  \
  "notification:{\"id\":\"-1\",\"from\":\"@snooker25\",\"to\":\"@snooker25\",\"key\":\"statsNotification.@"            \
  "snooker25\",\"value\":\"6356\",\"operation\":\"update\",\"epochMillis\":1734724406170,"                             \
  "\"messageType\":\"MessageType.key\",\"isEncrypted\":false,\"metadata\":null}"
#define test_3_length strlen(test_3_buffer)
int test_3_raw_notification() {
  size_t idx;
  int ret = atclient_utils_find_index_past_at_prompt((unsigned char *)test_3_buffer, test_3_length, &idx);
  if (ret != 0) {
    return 1;
  }

  expect_size_t("test 3", 0, idx);

  return 0;
}

#define test_4_buffer                                                                                                  \
  "@snooker25@notification:{\"id\":\"-1\",\"from\":\"@snooker25\",\"to\":\"@snooker25\",\"key\":\"statsNotification.@" \
  "snooker25\",\"value\":\"6356\",\"operation\":\"update\",\"epochMillis\":1734724406170,"                             \
  "\"messageType\":\"MessageType.key\",\"isEncrypted\":false,\"metadata\":null}"
#define test_4_length strlen(test_4_buffer)
int test_4_prompt_notification() {
  size_t idx;
  int ret = atclient_utils_find_index_past_at_prompt((unsigned char *)test_4_buffer, test_4_length, &idx);
  if (ret != 0) {
    return 1;
  }

  expect_size_t("test 4", 11, idx);

  return 0;
}

#define test_5_buffer "@data:ok"
#define test_5_length sizeof(test_5_buffer)
int test_5_data_response() {
  size_t idx;
  int ret = atclient_utils_find_index_past_at_prompt((unsigned char *)test_5_buffer, test_5_length, &idx);
  if (ret != 0) {
    return 1;
  }

  expect_size_t("test 5", 1, idx);

  return 0;
}

#define test_6_buffer "data:ok"
#define test_6_length sizeof(test_6_buffer)
int test_6_raw_data_response() {
  size_t idx;
  int ret = atclient_utils_find_index_past_at_prompt((unsigned char *)test_6_buffer, test_6_length, &idx);
  if (ret != 0) {
    return 1;
  }

  expect_size_t("test 6", 0, idx);

  return 0;
}

#define test_7_buffer "@snooker25@data:ok"
#define test_7_length sizeof(test_7_buffer)
int test_7_authed_data_response() {
  size_t idx;
  int ret = atclient_utils_find_index_past_at_prompt((unsigned char *)test_7_buffer, test_7_length, &idx);
  if (ret != 0) {
    return 1;
  }

  expect_size_t("test 7", 11, idx);

  return 0;
}

#define test_8_buffer "@error:AT0003-Invalid syntax : invalid command"
#define test_8_length sizeof(test_8_buffer)
int test_8_data_response() {
  size_t idx;
  int ret = atclient_utils_find_index_past_at_prompt((unsigned char *)test_8_buffer, test_8_length, &idx);
  if (ret != 0) {
    return 1;
  }

  expect_size_t("test 8", 1, idx);

  return 0;
}

#define test_9_buffer "error:AT0003-Invalid syntax : invalid command"
#define test_9_length sizeof(test_9_buffer)
int test_9_raw_data_response() {
  size_t idx;
  int ret = atclient_utils_find_index_past_at_prompt((unsigned char *)test_9_buffer, test_9_length, &idx);
  if (ret != 0) {
    return 1;
  }

  expect_size_t("test 9", 0, idx);

  return 0;
}

#define test_10_buffer "@snooker25@error:AT0003-Invalid syntax : invalid command"
#define test_10_length sizeof(test_10_buffer)
int test_10_authed_data_response() {
  size_t idx;
  int ret = atclient_utils_find_index_past_at_prompt((unsigned char *)test_10_buffer, test_10_length, &idx);
  if (ret != 0) {
    return 1;
  }

  expect_size_t("test 10", 11, idx);

  return 0;
}

#define test_11_buffer "@null"
#define test_11_length strlen(test_11_buffer)
int test_11_null_atdirectory() {
  size_t idx;
  int ret = atclient_utils_find_index_past_at_prompt((unsigned char *)test_11_buffer, test_11_length, &idx);
  if (ret != 0) {
    return 1;
  }

  expect_size_t("test 11", 1, idx);

  return 0;
}
