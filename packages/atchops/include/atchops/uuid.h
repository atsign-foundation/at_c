#ifndef ATCHOPS_UUID_H
#define ATCHOPS_UUID_H

#include <stddef.h>

/**
 * @brief Initializes the UUID generator. For example, opens /dev/urandom for reading
 *
 * @return int 0 on success
 */
int atchops_uuid_init(void);

/**
 * @brief Generate a UUID-v4 string
 *
 * @param uuidstr the buffer to store the UUID string
 * @param uuidstrlen the length of the buffer
 * @return int 0 on success, 1 on error
 */
int atchops_uuid_generate(char *uuidstr, const size_t uuidstrlen);

#endif
