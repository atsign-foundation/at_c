#ifndef ATAUTH_BUILD_ATKEYS_FILE_PATH_H
#define ATAUTH_BUILD_ATKEYS_FILE_PATH_H

/**
 * @brief Constructs the default atkeys file path for the given atsign. [Default path: $HOME/.atsign/keys/@atsign_key.atKeys]
 *
 * @param atkeys_path Pointer to store the null-terminated atkeys filepath (memory will be allocated by method)
 * @param atsign Pointer to atsign string
 * @return int 0 on success, non-zero on error
 */
int atauth_build_atkeys_file_path(char **atkeys_path, const char *atsign);

#endif //ATAUTH_BUILD_ATKEYS_FILE_PATH_H
