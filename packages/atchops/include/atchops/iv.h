
#ifndef ATCHOPS_IV_H
#define ATCHOPS_IV_H

#define ATCHOPS_IV_BUFFER_SIZE 16 // ivs are always 16 bytes long

/**
 * @brief Generates a random initialization vector (implied 16 bytes long)
 *
 * @param iv the buffer to store the generated IV
 * @return int 0 on success, non-zero on failure
 */
int atchops_iv_generate(unsigned char *iv);

/**
 * @brief Generates a random initialization vector and encodes it in base64
 *
 * @param ivbase64 the buffer to store the generated IV
 * @param ivbase64len the length of the buffer
 * @param ivbase64olen the length of the generated IV
 * @return int 0 on success, non-zero on failure
 */
int atchops_iv_generate_base64(unsigned char *ivbase64, const unsigned long ivbase64len, unsigned long *ivbase64olen);

#endif