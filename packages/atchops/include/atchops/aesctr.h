#ifndef ATCHOPS_AESCTR_H
#define ATCHOPS_AESCTR_H

#include "atchops/aes.h"
#include <stddef.h>

/**
 * @brief AES CTR encrypt plaintext to ciphertextbase64 (base64 encoded string)
 *
 * @param keybase64 the AES key encoded in base64
 * @param keybase64len the length of the keybase64 string buffer
 * @param keybits the AES key length in bits (e.g. AES-256 = 256 => ATCHOPS_AES_256)
 * @param iv the initialization vector (always 16 bytes long)
 * @param plaintext the plaintext to encrypt
 * @param plaintextlen the length of the plaintext string
 * @param ciphertextbase64 the ciphertext buffer to write to
 * @param ciphertextbase64len the memory allocated length of the ciphertext buffer
 * @param ciphertextbase64olen the written length of the ciphertext buffer
 * @return int 0 on success
 */
int atchops_aesctr_encrypt(const char *keybase64, const size_t keybase64len, const enum atchops_aes_size keybits,
                           unsigned char *iv, // always 16 bytes long
                           const unsigned char *plaintext, const size_t plaintextlen,
                           unsigned char *ciphertextbase64, const size_t ciphertextbase64len,
                           size_t *ciphertextbase64olen);

/**
 * @brief AES CTR decrypt ciphertextbase64 to plaintext
 *
 * @param keybase64 the AES key encoded in base64
 * @param keybase64len the length of the keybase64 string buffer
 * @param keybits the AES key length in bits (e.g. AES-256 = 256 => ATCHOPS_AES_256)
 * @param iv the initialization vector (always 16 bytes long)
 * @param ciphertextbase64 the ciphertext encoded in base64 to decrypt
 * @param ciphertextbase64len the length of the ciphertextbase64 string
 * @param plaintext the plaintext buffer to write to
 * @param plaintextlen the memory allocated length of the plaintext buffer
 * @param plaintextolen the written length of the plaintext buffer
 * @return int 0 on success
 */
int atchops_aesctr_decrypt(const char *keybase64, const size_t keybase64len, const enum atchops_aes_size keybits,
                           unsigned char *iv, // always 16 bytes long
                           const unsigned char *ciphertextbase64, const size_t ciphertextbase64len,
                           unsigned char *plaintext, const size_t plaintextlen, size_t *plaintextolen);

#endif
