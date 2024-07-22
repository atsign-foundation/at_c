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
 * @param keybits key length in bits (e.g. AES-256 = 256 => ATCHOPS_AES_256)
 * @return int 0 on success
 */
int atchops_aes_generate_key(unsigned char *key, const enum atchops_aes_size keybits);

#endif
