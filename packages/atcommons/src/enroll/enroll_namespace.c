#include "atcommons/enroll_namespace.h"

#include "cJSON.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <atlogger/atlogger.h>

#define TAG "enroll_namespace"

int atcommons_enroll_namespace_list_append(enroll_namespace_list_t **ns_list, enroll_namespace_t *ns) {
  if (ns == NULL) {
    atlogger_log(TAG, 0, "Namespace to append cannot be null\n");
    return -1;
  }

  // If the list's length is uninitialized (SIZE_MAX), set it to 0
  if ((*ns_list)->length == SIZE_MAX) {
    (*ns_list)->length = 0;
  }

  // Calculate new size
  const size_t new_length = (*ns_list)->length + 1;

  // Try reallocating memory for the array of enroll_namespace_t structs
  enroll_namespace_list_t *temp =
      realloc(*ns_list, sizeof(enroll_namespace_list_t) + sizeof(enroll_namespace_t *) * new_length);

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

int atcommons_enroll_namespace_list_from_string(char *json_str, enroll_namespace_list_t *ns_list) {
  int sep_count = 0;
  int ns_string_end = strlen(json_str);
  for (int i = 0; i < ns_string_end; i++) {
    if (json_str[i] == ':') {
      sep_count++;
      json_str[i] = '\0';
    }

    if (json_str[i] == ',') {
      json_str[i] = '\0';
    }
  }

  int pos = 0;
  enroll_namespace_t *ns_temp = NULL;
  for (int i = 0; i < sep_count; i++) {
    ns_temp = malloc(sizeof(enroll_namespace_t));
    ns_temp->name = strdup(json_str + pos);
    pos = strlen(json_str + pos) + 1;
    ns_temp->access = strdup(json_str + pos);
    atcommons_enroll_namespace_list_append(&ns_list, ns_temp);
    pos += strlen(json_str + pos) + 1;
  }

  return 0;
}
