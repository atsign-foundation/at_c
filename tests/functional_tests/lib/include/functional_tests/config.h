#ifndef FUNCTIONAL_TESTS_CONFIG_H
#define FUNCTIONAL_TESTS_CONFIG_H

#include <stddef.h>

#define ROOT_HOST "root.atsign.org"
#define ROOT_PORT 64

#define FIRST_ATSIGN "@12alpaca"
#define SECOND_ATSIGN "@12snowboating"

/**
 * @brief Get the atkeys file path for the given atSign.
 *
 * @param atsign the atSign string, must begin with @ (Example: "@bob")
 * @param atsignlen the length of the atsign string
 * @param path the output path string. Example output would be "keys/@bob_key.atKeys"
 * @param pathsize the allocated size of the path
 * @param pathlen the output length of the path
 * @return int, 0 on success
 */
int functional_tests_get_atkeys_path(const char *atsign, const size_t atsignlen, char *path, const size_t pathsize, size_t *pathlen);

#endif
