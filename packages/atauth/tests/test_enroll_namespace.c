#include "atlogger/atlogger.h"
#include "enroll_namespace.h"
#include <stdio.h>
#include <string.h>

#define TAG "test_enroll_namespace"

static int test_1a_parse_enroll_namespace_valid();
static int test_2a_parse_enroll_namespace_invalid();
static int test_2b_parse_enroll_namespace_invalid();
static int test_2c_parse_enroll_namespace_invalid();
static int test_2d_parse_enroll_namespace_invalid();
static int test_3a_to_json();

int main() {
  int ret = 0;
  atlogger_set_logging_level(ATLOGGER_LOGGING_LEVEL_INFO);

  ret += test_1a_parse_enroll_namespace_valid();
  ret += test_2a_parse_enroll_namespace_invalid();
  ret += test_2b_parse_enroll_namespace_invalid();
  ret += test_2c_parse_enroll_namespace_invalid();
  ret += test_2d_parse_enroll_namespace_invalid();
  ret += test_3a_to_json();

  if (ret > 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "%d tests failed\n", ret);
  }
  return ret;
}

#define input_1a "buzz:rw,wavi:r"
static int test_1a_parse_enroll_namespace_valid() {
  struct enroll_namespace ns;
  enroll_namespace_init(&ns);
  int ret = parse_enroll_namespace(input_1a, &ns);
  if (ret != 0) {
    atlogger_log(TAG " 1a", ATLOGGER_LOGGING_LEVEL_ERROR, "Failed to parse namespace list\n");
    return 1;
  }
  if (ns.len != 2) {
    atlogger_log(TAG " 1a", ATLOGGER_LOGGING_LEVEL_ERROR, "Incorrect length for list: expected 2, actual %zu\n",
                 ns.len);
    return 1;
  }
  if (strncmp(ns.namespaces[0], "buzz", 4) != 0) {
    atlogger_log(TAG " 1a", ATLOGGER_LOGGING_LEVEL_ERROR,
                 "Incorrect value for namespace[0]: expected buzz, actual %s\n", ns.namespaces[0]);
    return 1;
  }
  if (strncmp(ns.namespaces[1], "wavi", 4) != 0) {
    atlogger_log(TAG " 1a", ATLOGGER_LOGGING_LEVEL_ERROR,
                 "Incorrect value for namespace[1]: expected wavi, actual %s\n", ns.namespaces[1]);
    return 1;
  }
  if (ns.permissions[0] != np_read_write) {
    atlogger_log(TAG " 1a", ATLOGGER_LOGGING_LEVEL_ERROR, "Incorrect value for permission[0]: expected 3, actual %d\n",
                 ns.permissions[0]);
    return 1;
  }
  if (ns.permissions[1] != np_readonly) {
    atlogger_log(TAG " 1a", ATLOGGER_LOGGING_LEVEL_ERROR, "Incorrect value for permission[1]: expected 1, actual %d\n",
                 ns.permissions[1]);
    return 1;
  }
  enroll_namespace_free(&ns);
  return 0;
}

#define input_2a "buzz:rw,wavi"
static int test_2a_parse_enroll_namespace_invalid() {
  struct enroll_namespace ns;
  enroll_namespace_init(&ns);
  int ret = parse_enroll_namespace(input_2a, &ns);
  if (ret == 0) {
    atlogger_log(TAG " 2a", ATLOGGER_LOGGING_LEVEL_ERROR, "Expected '%s' to fail parsing\n", input_2a);
    return 1;
  }
  return 0;
}

#define input_2b "buzz:rw,"
static int test_2b_parse_enroll_namespace_invalid() {
  struct enroll_namespace ns;
  enroll_namespace_init(&ns);
  int ret = parse_enroll_namespace(input_2b, &ns);
  if (ret == 0) {
    atlogger_log(TAG " 2b", ATLOGGER_LOGGING_LEVEL_ERROR, "Expected '%s' to fail parsing\n", input_2b);
    return 1;
  }
  return 0;
}

#define input_2c "buzz:rwx"
static int test_2c_parse_enroll_namespace_invalid() {
  struct enroll_namespace ns;
  enroll_namespace_init(&ns);
  int ret = parse_enroll_namespace(input_2c, &ns);
  if (ret == 0) {
    atlogger_log(TAG " 2c", ATLOGGER_LOGGING_LEVEL_ERROR, "Expected '%s' to fail parsing\n", input_2c);
    return 1;
  }
  return 0;
}

#define input_2d "buzz:rw,wavi:"
static int test_2d_parse_enroll_namespace_invalid() {
  struct enroll_namespace ns;
  enroll_namespace_init(&ns);
  int ret = parse_enroll_namespace(input_2d, &ns);
  if (ret == 0) {
    atlogger_log(TAG " 2d", ATLOGGER_LOGGING_LEVEL_ERROR, "Expected '%s' to fail parsing\n", input_2d);
    return 1;
  }
  return 0;
}
#define expected_json_3a "{\"buzz\":\"rw\",\"wavi\":\"r\"}"
static int test_3a_to_json() {
  enum namespace_permissions perms[2] = {np_read_write, np_readonly};
  struct enroll_namespace ns = {
      .len = 2,
      .namespaces = NULL,
      .permissions = perms,
  };
  ns.namespaces = malloc(sizeof(char *) * 2);
  if (ns.namespaces == NULL) {
    atlogger_log(TAG " 3a", ATLOGGER_LOGGING_LEVEL_ERROR, "Failed to allocate ns.namespaces\n");
    return 1;
  }
  ns.namespaces[0] = malloc(sizeof(char) * 5);
  if (ns.namespaces == NULL) {
    atlogger_log(TAG " 3a", ATLOGGER_LOGGING_LEVEL_ERROR, "Failed to allocate ns.namespaces[0]\n");
    free(ns.namespaces);
    return 1;
  }
  ns.namespaces[1] = malloc(sizeof(char) * 5);
  if (ns.namespaces == NULL) {
    atlogger_log(TAG " 3a", ATLOGGER_LOGGING_LEVEL_ERROR, "Failed to allocate ns.namespaces[1]\n");
    free(ns.namespaces[0]);
    free(ns.namespaces);
    return 1;
  }

  memcpy(ns.namespaces[0], "buzz", 4);
  ns.namespaces[0][4] = 0;
  memcpy(ns.namespaces[1], "wavi", 4);
  ns.namespaces[1][4] = 0;

  char *json;
  int ret = enroll_namespace_to_json_string(&ns, &json);
  if (ret != 0) {
    atlogger_log(TAG " 3a", ATLOGGER_LOGGING_LEVEL_ERROR, "Failed to convert namespace struct to json string\n");
    free(ns.namespaces[0]);
    free(ns.namespaces[1]);
    free(ns.namespaces);
    return 1;
  }
  ret = strncmp(json, expected_json_3a, strlen(expected_json_3a));
  if (ret != 0) {
    atlogger_log(TAG " 3a", ATLOGGER_LOGGING_LEVEL_ERROR,
                 "json string output did not match expected result\n"
                 "\t\texpected: '%s'\n\t\tactual: '%s'\n",
                 expected_json_3a, json);
  }

  free(json);
  free(ns.namespaces[0]);
  free(ns.namespaces[1]);
  free(ns.namespaces);
  return 0;
}
