#ifndef ENROLL_NAMESPACE_STRUCT_H
#define ENROLL_NAMESPACE_STRUCT_H

#define MAX_NAMESPACES 10

typedef struct {
    char *name;
    char *access;
} EnrollNamespace;

typedef struct {
    EnrollNamespace *namespaces[MAX_NAMESPACES];
    int length;
} EnrollNamespaceList;

// Function to serialize enroll_namespace to JSON
int enroll_namespace_to_json(char *ns_str, EnrollNamespace *ns);

// Function to serialise a list of enroll_namespace[s]
int enroll_namespace_list_to_json(char **ns_list_string, EnrollNamespaceList *ns_list);

// Funtion to append namespace struct to namespaces list
int enroll_namespace_list_append(EnrollNamespaceList *ns_list, EnrollNamespace *ns);

#endif
