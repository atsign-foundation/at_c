#include "at_expect.c"
#include "atcommons/enroll_namespace.h"
#include "atlogger/atlogger.h"

#include <stdlib.h>
#include <string.h>

#define TAG "test_enroll_namespace_utils.c"

int test_enroll_namespace_to_json();
int test_enroll_namespace_list_to_json();

int main() {
  int ret = test_enroll_namespace_to_json();
  if (ret != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "%s failed\n", "test_enroll_namespace_to_json");
    return ret;
  }
  ret = test_enroll_namespace_list_to_json();
  return ret;
}

int test_enroll_namespace_to_json() {
  atcommons_enroll_namespace_t en;
  en.name = "ns1";
  en.access = "rw";
  char en_expected_json[] = "{\"ns1\":\"rw\"}";

  atcommons_enroll_namespace_t en2;
  en2.name = "ns2";
  en2.access = "r";
  char en2_expected_json[] = "{\"ns2\":\"r\"}";

  char *ns_json = NULL;
  size_t ns_json_len = 0;

  // test enroll namespace 1
  atcommons_enroll_namespace_to_json(NULL, 0, &ns_json_len, &en);
  size_t ns_json_size = sizeof(char) * ns_json_len + 1;
  ns_json = malloc(ns_json_size);
  int ret = atcommons_enroll_namespace_to_json(ns_json, ns_json_size, &ns_json_len, &en);
  if (ret != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atcommons_enroll_namespace_to_json: %d\n", ret);
  }
  ret = atcommons_string_expect(ns_json, en_expected_json);

  // test enroll namespace 2
  memset(ns_json, 0, ns_json_size);
  ns_json_len = 0;
  ret = atcommons_enroll_namespace_to_json(ns_json, ns_json_size, &ns_json_len, &en2);
  if (ret != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atcommons_enroll_namespace_to_json: %d\n", ret);
  }
  ret = atcommons_string_expect(ns_json, en2_expected_json);

  free(ns_json);
  return ret;
}

int test_enroll_namespace_list_to_json() {
  atcommons_enroll_namespace_t en;
  en.name = "ns1";
  en.access = "rw";

  atcommons_enroll_namespace_t en2;
  en2.name = "ns2";
  en2.access = "r";

  char en_expected_json[] = "{\"ns1\":\"rw\",\"ns2\":\"r\"}";

  atcommons_enroll_namespace_list_t *ns_list = malloc(sizeof(atcommons_enroll_namespace_list_t));
  atcommons_enroll_namespace_list_append(&ns_list, &en);
  atcommons_enroll_namespace_list_append(&ns_list, &en2);

  char *ns_list_json = NULL;
  size_t ns_list_json_len = 0;

  int ret = atcommons_enroll_namespace_list_to_json(&ns_list_json, &ns_list_json_len, ns_list);
  if (ret != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atcommons_enroll_namespace_list_to_json: %d\n", ret);
  }
  ret = atcommons_string_expect(ns_list_json, en_expected_json);

  free(ns_list_json);
  return ret;
}