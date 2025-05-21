#include "enroll_namespace.h"
#include "atclient/json.h"
#include "atlogger/atlogger.h"
#include <stdint.h>
#include <stdio.h>
#include <string.h>

void enroll_namespace_init(struct enroll_namespace *ns) {
  ns->len = 0;
  ns->namespaces = NULL;
  ns->permissions = NULL;
}

void enroll_namespace_free(struct enroll_namespace *ns) {
  if (ns->len > 0) {
    for (size_t i = 0; i < ns->len; i++) {
      if (ns->namespaces[i] != NULL) {
        free(ns->namespaces[i]);
      }
    }

    if (ns->namespaces != NULL) {
      free(ns->namespaces);
    }
    if (ns->permissions != NULL) {
      free(ns->permissions);
    }
  }
}

int parse_enroll_namespace(const char *input, struct enroll_namespace *output) {
  const char *TAG = "parse_enroll_namespace";

  size_t input_len = strlen(input);
  char *buffer = malloc(sizeof(char) * (input_len + 1));
  if (buffer == NULL) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "Failed to allocate memory for parse buffer\n");
    return 1;
  }
  memcpy(buffer, input, input_len);
  buffer[input_len] = 0;

  int sep_count = 0;
  int commas = 0;
  int permitopen_end = strlen(buffer);

  for (int i = 0; i < permitopen_end; i++) {
    if (buffer[i] == ':') {
      sep_count++;
      buffer[i] = '\0';
    }

    if (buffer[i] == ',') {
      commas++;
      buffer[i] = '\0';
    }
  }

  if (commas != sep_count - 1) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "namespace:permissions list has invalid format\n");
    free(buffer);
    return 1;
  }

  output->len = sep_count;
  output->namespaces = malloc(sep_count * sizeof(char *));
  if (output->namespaces == NULL) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "Failed to allocate namespaces list\n");
    free(buffer);
    return 1;
  }
  for (int i = 0; i < sep_count; i++) {
    output->namespaces[i] = NULL;
  }

  output->permissions = malloc(sep_count * sizeof(enum namespace_permissions));

  if (output->permissions == NULL) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "Failed to allocate permissions list\n");
    free(buffer);
    free(output->namespaces);
    return 1;
  }

  int pos = 0;

  for (int i = 0; i < sep_count; i++) {
    // Add the namespace to the namespace list
    size_t namespace_len = strlen(buffer + pos);
    (output->namespaces)[i] = malloc(sizeof(char) * (namespace_len + 1));
    if ((output->namespaces)[i] == NULL) {
      atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "Failed to allocate namespace string %d\n", i);
      free(buffer);
      enroll_namespace_free(output);
      return 1;
    }

    memcpy(output->namespaces[i], buffer + pos, namespace_len);
    output->namespaces[i][namespace_len] = 0;

    // Jump to the permission string
    pos += strlen(buffer + pos) + 1;

    size_t permission_len = strlen(buffer + pos);
    uint8_t permission_bits = 0;

    for (size_t j = 0; j < permission_len; j++) {
      switch ((buffer + pos)[j]) {
      case 'r':
        permission_bits |= 0b01;
        break;
      case 'w':
        permission_bits |= 0b10;
        break;
      default:
        atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "Unrecognized namespace permission value: %s\n", buffer + pos);
        free(buffer);
        enroll_namespace_free(output);
        return 1;
      }
    }

    switch (permission_bits) {
    case np_readonly:
    case np_read_write:
      output->permissions[i] = permission_bits;
      break;
    default:
      atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "Failed to parse namespace permissions %s\n", buffer + pos);
      free(buffer);
      enroll_namespace_free(output);
      return 1;
    }

    // Jump to the next namespace string
    pos += permission_len + 1;
  }
  free(buffer);

  return 0;
}

int enroll_namespace_to_json_string(struct enroll_namespace *ns, char **json_string) {
  const char *TAG = "enroll_namespace_to_json_string";
  cJSON *json = cJSON_CreateObject();
  if (json == NULL) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "Failed to allocate memory for cJSON object\n");
    return 1;
  }

  for (size_t i = 0; i < ns->len; i++) {
    switch (ns->permissions[i]) {
    case np_readonly:
      cJSON_AddStringToObject(json, ns->namespaces[i], "r");
      break;
    case np_read_write:
      cJSON_AddStringToObject(json, ns->namespaces[i], "rw");
      break;
    }
  }
  *json_string = cJSON_PrintUnformatted(json);
  cJSON_Delete(json);
  if (*json_string == NULL) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "Failed to allocate memory for cJSON print string\n");
    return 1;
  }

  return 0;
}
