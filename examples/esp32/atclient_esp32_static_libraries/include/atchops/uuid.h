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
 * @param uuid_str the buffer to store the UUID string
 * @param uuid_str_len the length of the buffer
 * @return int 0 on success, 1 on error
 */
int atchops_uuid_generate(char *uuid_str, const size_t uuid_str_len);

#endif
