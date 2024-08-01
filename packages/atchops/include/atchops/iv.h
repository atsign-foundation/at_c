#ifndef ATCHOPS_IV_H
#define ATCHOPS_IV_H

#include <stddef.h>

#define ATCHOPS_IV_BUFFER_SIZE 16 // non-base64 ivs are always 16 bytes long

/**
 * @brief Generates a random initialization vector (implied 16 bytes long)
 *
 * @param iv the buffer to store the generated IV
 * @return int 0 on success, non-zero on failure
 */
int atchops_iv_generate(unsigned char *iv);

#endif
