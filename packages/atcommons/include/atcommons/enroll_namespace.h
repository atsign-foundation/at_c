#ifndef ENROLL_NAMESPACE_STRUCT_H
#define ENROLL_NAMESPACE_STRUCT_H

#define MAX_NAMESPACES 10
#include <stddef.h>

typedef struct enroll_namespace {
  char *name;
  char *access;
} enroll_namespace_t;

typedef struct enroll_namespace_list {
  enroll_namespace_t *namespaces[MAX_NAMESPACES];
  int length;
} enroll_namespace_list_t;

// Function to serialize enroll_namespace to JSON
int atcommons_enroll_namespace_to_json(char *ns_str, enroll_namespace_t *ns);

// Function to serialise a list of enroll_namespace[s]
int atcommons_enroll_namespace_list_to_json(char *ns_list_string, size_t *ns_list_str_len, enroll_namespace_list_t *ns_list);

// Funtion to append namespace struct to namespaces list
int atcommons_enroll_namespace_list_append(enroll_namespace_list_t *ns_list, enroll_namespace_t *ns);

#endif
