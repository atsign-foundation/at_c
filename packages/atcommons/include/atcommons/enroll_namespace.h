#ifndef ATCOMMONS_ENROLL_NAMESPACE_H
#define ATCOMMONS_ENROLL_NAMESPACE_H

#include <stddef.h>

typedef struct {
  char *name;
  char *access;
} atcommons_enroll_namespace_t;

typedef struct {
  size_t length;
  atcommons_enroll_namespace_t *namespaces[];
} atcommons_enroll_namespace_list_t;

/**
 * @brief serializes enroll_namespace struct to JSON string
 *
 * Note: To caclulate expected length, use method with ns_str set to null and ns_str_size set to 0
 *
 * @param ns_str pointer to a char buffer where the JSON string will be stored
 * @param ns_str_size size of the ns_str char buffer, to ensure safe writing
 * @param ns_str_len pointer to where the length of the JSON string will be
 * stored by the method
 * @param ns enroll_namespace struct which needs to be serialized
 * @return int 0 on success, non-zero int on failure
 */
int atcommons_enroll_namespace_to_json(char *ns_str, const size_t ns_str_size, size_t *ns_str_len,
                                       const atcommons_enroll_namespace_t *ns);

/**
 * @brief serialises a list of enroll_namespace[s] to JSON string
 *
 * @param ns_list_string pointer to the string buffer where the JSON string
 * should be stored
 * @param ns_list_str_len pointer to store the length of the generated
 * enroll_namepace_list JSON string
 * @param ns_list pointer to the enroll_namespace_list struct that needs to be
 * serialized
 * @return int 0 on success, non-zero int on failure
 */
int atcommons_enroll_namespace_list_to_json(char **ns_list_string, size_t *ns_list_str_len,
                                            const atcommons_enroll_namespace_list_t *ns_list);

/**
 * @brief appends an enroll_namespace struct to an enroll_namespace_list struct.
 * Realloc's new memry required to append the new enroll_namespace
 *
 * Note: It is recommended to use this method to append an enroll_namespace
 * struct as this method sets necessary interal params that will be used while
 * serializing the enroll_namespace_list to JSON string
 *
 * @param ns_list double pointer to the enroll_namespace_list struct to which
 * the new namespace should be appended
 * @param ns pointer to the enroll_namespace struct that needs to be appended to
 * the list
 * @return int 0 on success, non-zero int on failure
 */
int atcommons_enroll_namespace_list_append(atcommons_enroll_namespace_list_t **ns_list,
                                           atcommons_enroll_namespace_t *ns);

#endif
