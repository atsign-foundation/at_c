#ifndef FUNCTIONAL_TESTS_CONFIG_H
#define FUNCTIONAL_TESTS_CONFIG_H

#define ROOT_HOST "root.atsign.org"
#define ROOT_PORT 64

#define FIRST_ATSIGN "@12alpaca1"
#define SECOND_ATSIGN "@12snowboating"

/**
 * @brief Get the atkeys file path for the given atSign. Expected to be in the home directory of the user. Example: /Users/bob/.atsign/keys/@jeremy_0_key.atKeys
 *
 * @param atsign the atSign string, must begin with @ (Example: "@bob")
 * @param atsignlen the length of the atsign string
 * @param path the output path string. Example output would be "/Users/bob/.atsign/keys/@bob_key.atKeys"
 * @param pathsize the allocated size of the path
 * @param pathlen the output length of the path
 * @return int, 0 on success
 */
int get_atkeys_path(char *atsign, const size_t atsignlen, char *path, const size_t pathsize, size_t *pathlen);

#endif
