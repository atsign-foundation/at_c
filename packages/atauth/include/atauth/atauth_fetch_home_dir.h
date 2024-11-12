#ifndef ATAUTH_FETCH_HOME_DIR_H
#define ATAUTH_FETCH_HOME_DIR_H

/**
 * @brief fetches the home directory of the current user (platform independent)
 *
 * @param home_dir A buffer where the home directory path will be stored. Memory will be allocated by the method.
 *
 * Note: path always has a trailing seperator ('/' or '\\' based on platform)
 *
 * @return 0 on success, non-zero on failure.
 */
int atauth_get_home_directory(char **home_dir);

#endif // ATAUTH_FETCH_HOME_DIR_H