#include "at_expect.c"
#include "atcommons/enroll_namespace.h"
#include "atlogger/atlogger.h"

#include <stdlib.h>
#include <string.h>

#define TAG "test_enroll_namespace_utils.c"

int test_enroll_namespace_to_json();
int test_enroll_namespace_list_to_json();
int test_enroll_namespace_list_from_string();

int main() {
  int ret = test_enroll_namespace_to_json();
  if (ret != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "%s failed\n", "test_enroll_namespace_to_json: %d", ret);
    return ret;
  }
  ret = test_enroll_namespace_list_to_json();
  if(ret != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "%s failed\n", "test_enroll_namespace_list_to_json: %d", ret);
    return ret;
  }
  ret = test_enroll_namespace_list_from_string();
  if(ret != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "%s failed\n", "test_enroll_namespace_list_from_string: %d", ret);
  }
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

int test_enroll_namespace_list_from_string() {
  char *nsl_str_1 = "ns1:rw,ns2:r";
  char *nsl_str_2 = "ns3:rw";
  char *nsl_invalid_str_1 = "ns4";
  char *nsl_invalid_str_2 = "ns5:";
  atcommons_enroll_namespace_list_t *nsl = malloc(sizeof(atcommons_enroll_namespace_list_t));

  int ret = atcommons_enroll_namespace_list_from_string(&nsl, nsl_str_1);
  if (ret != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atcommons_enroll_namespace_list_from_string(ns string 1): %d\n", ret);
    return ret;
  }
  ret = atcommons_enroll_namespace_list_from_string(&nsl, nsl_str_2);
  if (ret != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atcommons_enroll_namespace_list_from_string(ns string 2): %d\n", ret);
    return ret;
  }
  ret = atcommons_enroll_namespace_list_from_string(&nsl, nsl_invalid_str_1);
  if (ret != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atcommons_enroll_namespace_list_from_string(ns string 3): %d\n", ret);
    return ret;
  }
  ret = atcommons_enroll_namespace_list_from_string(&nsl, nsl_invalid_str_2);
  if (ret != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atcommons_enroll_namespace_list_from_string(ns string 4): %d\n", ret);
    return ret;
  }

  const size_t ns_name_len = 3;
  const size_t ns_access_len = 2;
  if(strncmp(nsl->namespaces[0]->name, "ns1", ns_name_len) || strncmp(nsl->namespaces[0]->access, "rw", ns_access_len)) {
    ret = 1;
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "test_enroll_namespace_list_from_string case 1: failed\n");
    return ret;
  }
  if(strncmp(nsl->namespaces[1]->name, "ns2", ns_name_len) || strncmp(nsl->namespaces[1]->access, "r", ns_access_len - 1)) {
    ret = 1;
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "test_enroll_namespace_list_from_string case 2: failed\n");
    return ret;
  }
  if(strncmp(nsl->namespaces[2]->name, "ns3", ns_name_len) || strncmp(nsl->namespaces[2]->access, "rw", ns_access_len)) {
    ret = 1;
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "test_enroll_namespace_list_from_string case 3: failed\n");
    return ret;
  }

  // following two test cases are negative. Them being NULL is expected behaviour
  if(nsl->namespaces[3]->name != NULL || nsl->namespaces[3]->access != NULL) {
    ret = 1;
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "test_enroll_namespace_list_from_string case 4: failed\n");
    return ret;
  }
  if(nsl->namespaces[4]->name != NULL || nsl->namespaces[4]->access != NULL) {
    ret = 1;
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "test_enroll_namespace_list_from_string case 5: failed\n");
    return ret;
  }

  return ret;
}