#include "atlogger/atlogger.h"
#include "enroll_response.h"
#include <stdio.h>
#include <string.h>

#define TAG "test_enroll_response"

static int test_1a_enroll_response();
static int test_1b_malformed_responses();

int main() {
  int ret = 0;
  atlogger_set_logging_level(ATLOGGER_LOGGING_LEVEL_INFO);

  ret += test_1a_enroll_response();
  ret += test_1b_malformed_responses();

  if (ret != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "%d tests failed\n", ret);
  }

  return ret;
}

#define t1a_buffer "data:{\"enrollmentId\":\"705fc12e-b890-4703-abba-da11a396eb90\",\"status\":\"approved\"}"

static int test_1a_enroll_response() {
  struct enroll_response response;

  int ret = parse_enrollment_response(t1a_buffer, &response);
  if (ret != 0) {
    atlogger_log(TAG " 1a", ATLOGGER_LOGGING_LEVEL_ERROR, "Expected posititve return code from parse, got %d\n", ret);
    return 1;
  }

  // check id
  if (response.enrollment_id == NULL) {
    atlogger_log(TAG " 1a", ATLOGGER_LOGGING_LEVEL_ERROR, "Expected response.enrollment_id to be non-NULL\n");
    free_enroll_response(&response);
    return 1;
  }
  size_t expected_id_len = strlen("705fc12e-b890-4703-abba-da11a396eb90");
  size_t actual_id_len = strlen(response.enrollment_id);
  if (actual_id_len != expected_id_len) {
    atlogger_log(TAG " 1a", ATLOGGER_LOGGING_LEVEL_ERROR,
                 "Expected id length doesn't match actual id length:\n"
                 "\t\texpected: %zu\n"
                 "\t\tactual: %zu",
                 expected_id_len, actual_id_len);
    free_enroll_response(&response);
    return 1;
  }
  ret = strncmp(response.enrollment_id, "705fc12e-b890-4703-abba-da11a396eb90", expected_id_len);
  if (ret != 0) {
    atlogger_log(TAG " 1a", ATLOGGER_LOGGING_LEVEL_ERROR,
                 "Expected id doesn't match actual id:\n"
                 "\t\texpected: '%s'\n"
                 "\t\tactual: '%s'",
                 "705fc12e-b890-4703-abba-da11a396eb90", response.enrollment_id);
    free_enroll_response(&response);
    return 1;
  }
  // check status
  if (response.status == NULL) {
    atlogger_log(TAG " 1a", ATLOGGER_LOGGING_LEVEL_ERROR, "Expected response.status to be non-NULL\n");
    free_enroll_response(&response);
    return 1;
  }
  size_t expected_status_len = strlen("approved");
  size_t actual_status_len = strlen(response.status);
  if (actual_status_len != expected_status_len) {
    atlogger_log(TAG " 1a", ATLOGGER_LOGGING_LEVEL_ERROR,
                 "Expected status length doesn't match actual status length:\n"
                 "\t\texpected: %zu\n"
                 "\t\tactual: %zu\n",
                 expected_status_len, actual_status_len);
    free_enroll_response(&response);
    return 1;
  }
  ret = strncmp(response.status, "approved", expected_status_len);
  if (ret != 0) {
    atlogger_log(TAG " 1a", ATLOGGER_LOGGING_LEVEL_ERROR,
                 "Expected status doesn't match actual status:\n"
                 "\t\texpected: '%s'\n"
                 "\t\tactual: '%s'\n",
                 "approved", response.status);
    free_enroll_response(&response);
    return 1;
  }

  free_enroll_response(&response);
  return 0;
}

// well-formed JSON with missing or non-string mandatory fields must fail,
// not return 0 with NULL fields the callers strlen unconditionally
static int test_1b_malformed_responses() {
  const char *malformed[] = {
      "data:{\"status\":\"pending\"}",                            // missing enrollmentId
      "data:{\"enrollmentId\":\"abc\"}",                          // missing status
      "data:{\"enrollmentId\":42,\"status\":\"pending\"}",        // non-string enrollmentId
      "data:{\"enrollmentId\":\"abc\",\"status\":null}",          // non-string status
  };
  int failures = 0;
  for (size_t i = 0; i < sizeof(malformed) / sizeof(malformed[0]); i++) {
    struct enroll_response response;
    if (parse_enrollment_response(malformed[i], &response) == 0) {
      atlogger_log(TAG " 1b", ATLOGGER_LOGGING_LEVEL_ERROR, "Expected parse failure for: %s\n", malformed[i]);
      free_enroll_response(&response);
      failures++;
    }
  }
  return failures;
}
