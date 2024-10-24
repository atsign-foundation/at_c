#include "atcommons/enroll_namespace.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "../../../../_deps/cjson-src/cJSON.h"

#include <atlogger/atlogger.h>

#define TAG "enroll_namespace"

int atcommons_enroll_namespace_list_append(enroll_namespace_list_t **ns_list, enroll_namespace_t *ns) {
  enroll_namespace_list_t *temp = realloc(*ns_list, sizeof(enroll_namespace_list_t) + sizeof(enroll_namespace_t*) * ((*ns_list)->length + 1));

  if (temp == NULL) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "Unable to realloc memory for enroll namespace list\n");
    return -1;
  }

  // Add the new namespace to the end of the list
  temp->namespaces[temp->length] = ns;
  temp->length++;

  // Update the original ns_list to point to the new (reallocated) memory
  *ns_list = temp;

  return 0;
}

int atcommons_enroll_namespace_to_json(char *ns_str, enroll_namespace_t *ns) {
  if (ns_str == NULL || ns == NULL) {
    return -1;
  }

  snprintf(ns_str, strlen(ns->name) + strlen(ns->access) + 10, "{\"%s\":\"%s\"}", ns->name, ns->access);

  return 0;
}

int atcommons_enroll_namespace_list_to_json(char *ns_list_string, size_t *ns_list_str_len,
                                            enroll_namespace_list_t *ns_list) {
  if (ns_list == NULL) {
    return -1;
  }

  cJSON *json_obj = cJSON_CreateObject();
  for (size_t ns_elmnt = 0; ns_elmnt < ns_list->length; ns_elmnt++) {
    cJSON_AddStringToObject(json_obj, ns_list->namespaces[ns_elmnt]->name, ns_list->namespaces[ns_elmnt]->access);
  }

  // Calculate the string length if requested
  if (ns_list_str_len != NULL) {
    *ns_list_str_len = strlen(cJSON_PrintUnformatted(json_obj)) + 1; // +1 for null-terminator
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_DEBUG, "ns list length is %lu\n", *ns_list_str_len);
  }

  if (ns_list_string != NULL) {
    char *temp_json_str = cJSON_PrintUnformatted(json_obj);
    if (temp_json_str) {
      strncpy(ns_list_string, temp_json_str, *ns_list_str_len);
    }
  }

  if (json_obj) {
    cJSON_Delete(json_obj);
  }

  return 0;
}
