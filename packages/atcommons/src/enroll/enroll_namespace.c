#include "atcommons/enroll_namespace.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "../../../../_deps/cjson-src/cJSON.h"

int atcommons_enroll_namespace_list_append(enroll_namespace_list_t *ns_list, enroll_namespace_t *ns) {
  if (ns_list->length >= MAX_NAMESPACES) {
    return -1;
  }

  ns_list->namespaces[ns_list->length] = ns;
  ns_list->length++;
  return 0;
}

int atcommons_enroll_namespace_to_json(char *ns_str, enroll_namespace_t *ns) {
  if (ns_str == NULL) {
    return -1;
  }

  snprintf(ns_str, "{\"%s\":\"%s\"}", ns->name, ns->access);

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

  if (ns_list_str_len != NULL) {
    // If ns_list_string is NULL populate ns_list_str_len with the calcualted string length.
    // Can be used to caclualate the amount of memory that needs to be allocated
    *ns_list_str_len = strlen(cJSON_PrintUnformatted(json_obj));
  }

  if (ns_list_string == NULL) {
    return 1;
  }
  ns_list_string = cJSON_PrintUnformatted(json_obj);

  if (json_obj) {
    cJSON_Delete(json_obj); // free the cJSON object
  }
  return 0;
}
