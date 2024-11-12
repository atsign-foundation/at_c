#ifndef FUNCTIONAL_TESTS_CONFIG_H
#define FUNCTIONAL_TESTS_CONFIG_H
#ifdef __cplusplus
extern "C" {
#endif

#include <stddef.h>

#define ATDIRECTORY_HOST "vip.ve.atsign.zone"
#define ATDIRECTORY_PORT 64

#define FIRST_ATSIGN "@purnima🛠"
#define SECOND_ATSIGN "@bob🛠"

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
int functional_tests_get_atkeys_path(const char *atsign, const size_t atsignlen, char *path, const size_t pathsize,
                                     size_t *pathlen);

#ifdef __cplusplus
}
#endif
#endif
