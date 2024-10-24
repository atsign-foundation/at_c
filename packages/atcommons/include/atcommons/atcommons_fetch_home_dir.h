#ifndef ATCOMMONS_FETCH_HOME_DIR_H
#define ATCOMMONS_FETCH_HOME_DIR_H

/**
 * Function to get the home directory of the current user.
 *
 * @param home_dir A buffer where the home directory path will be stored.
 *                 Ensure that the buffer size is at least PATH_MAX.
 *
 * @return 0 on success, -1 on failure.
 */
int atcommons_get_home_directory(char *home_dir);

#endif // ATCOMMONS_FETCH_HOME_DIR_H