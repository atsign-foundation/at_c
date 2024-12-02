#include "atcommons/enroll_namespace.h"

#include "cJSON.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <atlogger/atlogger.h>

#define TAG "enroll_namespace"

int atcommons_enroll_namespace_list_append(atcommons_enroll_namespace_list_t **ns_list,
                                           atcommons_enroll_namespace_t *ns) {
  // allocate enough memory for enroll_namespace_list struct, and the number of atcommons_enroll_namespace_t structs
  // that are in the list
  atcommons_enroll_namespace_list_t *temp =
      realloc(*ns_list, sizeof(atcommons_enroll_namespace_list_t) +
                            sizeof(atcommons_enroll_namespace_t) * ((*ns_list)->length + 1));

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

int atcommons_enroll_namespace_to_json(char *ns_str, const size_t ns_str_size, size_t *ns_str_len,
                                       const atcommons_enroll_namespace_t *ns) {
  if (ns == NULL) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "ns(namespace) cannot be null\n");
    return -1;
  }
  if (ns_str == NULL && ns_str_size == 0) {
    *ns_str_len = snprintf(NULL, 0, "{\"%s\":\"%s\"}", ns->name, ns->access) + 1; // +1 for \0
  }

  *ns_str_len = snprintf(ns_str, ns_str_size, "{\"%s\":\"%s\"}", ns->name, ns->access);

  return 0;
}

int atcommons_enroll_namespace_list_to_json(char **ns_list_string, size_t *ns_list_str_len,
                                            const atcommons_enroll_namespace_list_t *ns_list) {
  if (ns_list == NULL) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "ns_list(namespace list) cannot be null\n");
    return -1;
  }
  if (ns_list_str_len == NULL) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "ns_list_str_len(namespace_list string length) cannot be null\n");
    return -1;
  }
  // Create a new cJSON object
  cJSON *json_obj = cJSON_CreateObject();
  if (json_obj == NULL) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "Failed to create JSON object\n");
    return -1;
  }

  for (size_t ns_elmnt = 0; ns_elmnt < ns_list->length; ns_elmnt++) {
    cJSON_AddStringToObject(json_obj, ns_list->namespaces[ns_elmnt]->name, ns_list->namespaces[ns_elmnt]->access);
  }

  *ns_list_string = cJSON_PrintUnformatted(json_obj);
  if (*ns_list_string == NULL) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "Failed to print JSON\n");
    cJSON_Delete(json_obj);
    return -1;
  }
  if (ns_list_str_len != NULL) {
    *ns_list_str_len = strlen(*ns_list_string);
  }

  cJSON_Delete(json_obj);
  return 0;
}
