#include "atcommons/enroll_namespace.h"

#include "atcommons/json.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <atlogger/atlogger.h>

#define TAG "enroll_namespace"

int atcommmons_init_enroll_namespace_list(atcommons_enroll_namespace_list_t *ns_list) {
  if(ns_list == NULL) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "Memory not allocated for namespace list struct\n");
    return -1;
  }

  memset(ns_list, 0, sizeof(atcommons_enroll_namespace_list_t));

  return 0;
}

int atcommons_enroll_namespace_list_append(atcommons_enroll_namespace_list_t **ns_list,
                                           atcommons_enroll_namespace_t *ns) {
  if (ns == NULL) {
    atlogger_log(TAG, 0, "Namespace to append cannot be null\n");
    return -1;
  }

  // If the list's length is uninitialized (SIZE_MAX), set it to 0
  if ((*ns_list)->length == SIZE_MAX) {
    (*ns_list)->length = 0;
  }

  const size_t new_length = (*ns_list)->length + 1;
  // Try reallocating memory for the array of enroll_namespace_t structs
  atcommons_enroll_namespace_list_t *temp = realloc(*ns_list, sizeof(atcommons_enroll_namespace_list_t) +
                                                                  sizeof(atcommons_enroll_namespace_t *) * new_length);
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

#ifdef ATCOMMONS_JSON_PROVIDER_CJSON
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
#else
  #error "JSON provider not supported"
#endif

int atcommons_enroll_namespace_list_from_string(atcommons_enroll_namespace_list_t **ns_list, char *json_str) {
  int sep_count = 0;
  const int ns_string_end = strlen(json_str);
  int ret = 0;

  // Count seperator in the namespace list string. Replaces all occurences of ':' and ',' to '\0'
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

  atcommons_enroll_namespace_t *ns_temp = NULL;
  for (int i = 0; i < sep_count; i++) {
    ns_temp = malloc(sizeof(atcommons_enroll_namespace_t));
    ns_temp->name = strdup(json_str + pos);
    pos += strlen(json_str + pos) + 1;
    if(json_str + pos == NULL) {
      atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "Invalid namespace access value\n");
      ret = 1;
      return ret;
    }
    ns_temp->access = strdup(json_str + pos);

    if ((ret = atcommons_enroll_namespace_list_append(ns_list, ns_temp)) != 0) {
      atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR,
                   "Failed appending ns to ns_list | atcommons_enroll_namespace_list_append: %d", ret);
      return ret;
    }
    pos += strlen(json_str + pos) + 1;
  }
  exit: { return ret; }
}