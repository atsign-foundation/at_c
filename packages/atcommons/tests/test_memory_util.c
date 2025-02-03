#include "atlogger/atlogger.h"
#include <atcommons/memory_util.h>

static int test1a_valid_basic();
static int test1b_valid_custom_free();
static int test1c_valid_success_free();
static int test2a_invalid_exceed_length();
static int test2b_invalid_create_length();
static int test2c_invalid_append();
static int test2d_invalid_delete_index();

#define TAG "test_memory_util"
int main() {
  int ret = 0;
  atlogger_set_logging_level(ATLOGGER_LOGGING_LEVEL_INFO);

  ret += test1a_valid_basic();
  ret += test1b_valid_custom_free();
  ret += test1c_valid_success_free();
  ret += test2a_invalid_exceed_length();
  ret += test2b_invalid_create_length();
  ret += test2c_invalid_append();
  ret += test2d_invalid_delete_index();

  if (ret != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "%d tests failed\n", ret);
  }

  return ret;
}

static int test1a_valid_basic() {
  int ret;
  struct atcommons_memlist memlist = atcommons_memlist_create(2);

  char *a = malloc(16);
  ret = atcommons_memlist_add(&memlist, a, true, NULL);
  if (ret != 0) {
    atlogger_log(TAG " 1a", ATLOGGER_LOGGING_LEVEL_ERROR, "Failed to append a to memlist: %d\n", ret);
    atcommons_memlist_failure_free(&memlist);
    return 1;
  }

  unsigned char *b = malloc(32);
  ret = atcommons_memlist_add(&memlist, b, false, NULL);
  if (ret != 0) {
    atlogger_log(TAG " 1a", ATLOGGER_LOGGING_LEVEL_ERROR, "Failed to append b to memlist: %d\n", ret);
    atcommons_memlist_failure_free(&memlist);
    return 1;
  }

  atcommons_memlist_failure_free(&memlist);
  return 0;
}

static void free1b_char_array(void *ptr) { free(ptr); }
static int test1b_valid_custom_free() {
  int ret;
  struct atcommons_memlist memlist = atcommons_memlist_create(2);

  char *a = malloc(16);
  ret = atcommons_memlist_add(&memlist, a, true, free1b_char_array);
  if (ret != 0) {

    atlogger_log(TAG " 1b", ATLOGGER_LOGGING_LEVEL_ERROR, "Failed to append a to memlist: %d\n", ret);
    atcommons_memlist_failure_free(&memlist);
    return 1;
  }

  unsigned char *b = malloc(32);
  ret = atcommons_memlist_add(&memlist, b, false, NULL);
  if (ret != 0) {
    atlogger_log(TAG " 1b", ATLOGGER_LOGGING_LEVEL_ERROR, "Failed to append b to memlist: %d\n", ret);
    atcommons_memlist_failure_free(&memlist);
    return 1;
  }

  atcommons_memlist_failure_free(&memlist);
  return 0;
}

static int test1c_valid_success_free() {
  int ret;
  struct atcommons_memlist memlist = atcommons_memlist_create(2);

  char *a = malloc(16);
  ret = atcommons_memlist_add(&memlist, a, true, NULL);
  if (ret != 0) {

    atlogger_log(TAG " 1c", ATLOGGER_LOGGING_LEVEL_ERROR, "Failed to append a to memlist: %d\n", ret);
    atcommons_memlist_failure_free(&memlist);
    return 1;
  }

  unsigned char *b = malloc(32);
  ret = atcommons_memlist_add(&memlist, b, false, NULL);
  if (ret != 0) {
    atlogger_log(TAG " 1c", ATLOGGER_LOGGING_LEVEL_ERROR, "Failed to append b to memlist: %d\n", ret);
    atcommons_memlist_failure_free(&memlist);
    return 1;
  }

  atcommons_memlist_success_free(&memlist);

  if (memlist.allocated != 0b10) {
    atlogger_log(TAG " 1c", ATLOGGER_LOGGING_LEVEL_ERROR,
                 "memlist.allocated (after success_free) has an unexpected value (expected %u, actual %u)\n", 0b10,
                 memlist.allocated);
    atcommons_memlist_failure_free(&memlist);
    return 1;
  }

  atcommons_memlist_failure_free(&memlist);
  if (memlist.allocated != 0) {
    atlogger_log(TAG " 1c", ATLOGGER_LOGGING_LEVEL_ERROR,
                 "memlist.allocated (after failure_free) has an unexpected value (expected %u, actual %u)\n", 0,
                 memlist.allocated);
    return 1;
  }
  return 0;
}

// can use stack memory in this since we aren't testing any free capability
static int test2a_invalid_exceed_length() {
  int ret;
  struct atcommons_memlist memlist = atcommons_memlist_create(1);

  char *a = "foo";
  ret = atcommons_memlist_add(&memlist, a, true, NULL);
  if (ret != 0) {
    atlogger_log(TAG " 2a", ATLOGGER_LOGGING_LEVEL_ERROR, "Failed to append a to memlist: %d\n", ret);
    return 1;
  }

  unsigned char *b = (unsigned char *)"bar";
  ret = atcommons_memlist_add(&memlist, b, false, NULL);
  if (ret == 0) {
    atlogger_log(TAG " 2a", ATLOGGER_LOGGING_LEVEL_ERROR,
                 "Expected atcommons_memlist_append to fail due to exceeding length\n");
    return 1;
  }

  return 0;
}

static int test2b_invalid_create_length() {
  struct atcommons_memlist memlist = atcommons_memlist_create(ATCOMMONS_MEMLIST_SIZE + 1);

  if (memlist.len != ATCOMMONS_MEMLIST_SIZE) {
    atlogger_log(TAG " 2b", ATLOGGER_LOGGING_LEVEL_ERROR, "Expected memlist size to be capped at %d",
                 ATCOMMONS_MEMLIST_SIZE);
    return 1;
  }

  return 0;
}

static int test2c_invalid_append() {
  int ret;
  struct atcommons_memlist memlist = atcommons_memlist_create(2);
  ret = atcommons_memlist_add(&memlist, NULL, false, NULL);
  if (ret == 0) {
    atlogger_log(TAG " 2a", ATLOGGER_LOGGING_LEVEL_ERROR,
                 "Expected atcommons_memlist_append to fail due to invalid input\n");
    return 1;
  }

  return 0;
}

static int test2d_invalid_delete_index() {
  int ret;
  struct atcommons_memlist memlist = atcommons_memlist_create(2);
  ret = atcommons_memlist_index_free(&memlist, 0);
  if (ret == 0) {
    atlogger_log(TAG " 2a", ATLOGGER_LOGGING_LEVEL_ERROR,
                 "Expected atcommons_memlist_index_free to fail due to unallocated index\n");
    return 1;
  }

  ret = atcommons_memlist_index_free(&memlist, 3);
  if (ret == 0) {
    atlogger_log(TAG " 2a", ATLOGGER_LOGGING_LEVEL_ERROR,
                 "Expected atcommons_memlist_index_free to fail due to out of bounds index\n");
    return 1;
  }

  return 0;
}
