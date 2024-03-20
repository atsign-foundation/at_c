#ifndef ATCHOPS_AES_H
#define ATCHOPS_AES_H

#include <stddef.h>

enum atchops_aes_size {
  ATCHOPS_AES_NONE = 0,
  ATCHOPS_AES_128 = 128, // not tested
  ATCHOPS_AES_256 = 256,
};

/**
 * @brief Generate an AES key of size keylen bits
 *
 * @param key key buffer of size (keylen/8) bytes
 * @param keysize key length in bits (e.g. AES-256 = 256 => ATCHOPS_AES_256)
 * @return int 0 on success
 */
int atchops_aes_generate_key(unsigned char *key, const enum atchops_aes_size keysize);

/**
 * @brief Generate an AES key of size keylen bits encoded in base 64
 *
 * @param keybase64 key buffer to hold base64 string
 * @param keybase64len the allocated length of the key buffer
 * @param keybase64olen the written length of the key buffer
 * @param keysize the AES key length in bits (e.g. AES-256 = 256 => ATCHOPS_AES_256)
 * @return int 0 on success
 */
int atchops_aes_generate_keybase64(unsigned char *keybase64, const size_t keybase64len,
                                   size_t *keybase64olen, const enum atchops_aes_size keysize);

#endif
