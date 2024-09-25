#ifndef ENROLL_NAMESPACE_STRUCT_H
#define ENROLL_NAMESPACE_STRUCT_H

#define MAX_NAMESPACES 10

typedef struct {
    char *name;
    char *access;
} enroll_namespace;

typedef struct {
    enroll_namespace *namespaces[MAX_NAMESPACES];
    int length;
} enroll_namespace_list;

// Function to serialize enroll_namespace to JSON
int enroll_namespace_to_json(char *ns_str, enroll_namespace *ns);

// Function to serialise a list of enroll_namespace[s]
int enroll_namespace_list_to_json(char **ns_list_string, enroll_namespace_list *ns_list);

// Funtion to append namespace struct to namespaces list
int enroll_namespace_list_append(enroll_namespace_list *ns_list, enroll_namespace *ns);

#endif
