#ifndef ATCHOPS_AESCTR_H
#define ATCHOPS_AESCTR_H

#include "atchops/aes.h"
#include <stddef.h>

/**
 * @brief AES CTR encrypt plaintext to ciphertextbase64 (base64 encoded string)
 *
 * @param key the AES key in raw bytes (if key is 256 bits (32 bytes) then keybits should be ATCHOPS_AES_256)
 * @param keybits the AES key length in bits (e.g. AES-256 = 256 => ATCHOPS_AES_256)
 * @param iv the initialization vector (always 16 bytes long)
 * @param plaintext the plaintext to encrypt
 * @param plaintextlen the length of the plaintext string
 * @param ciphertext the ciphertext buffer to write to
 * @param ciphertextsize the memory allocated length of the ciphertext buffer
 * @param ciphertextlen the written length of the ciphertext buffer
 * @return int 0 on success
 */
int atchops_aesctr_encrypt(const unsigned char *key, const enum atchops_aes_size keybits,
                           unsigned char *iv, // always 16 bytes long
                           const unsigned char *plaintext, const size_t plaintextlen, unsigned char *ciphertext,
                           const size_t ciphertextsize, size_t *ciphertextlen);

/**
 * @brief AES CTR decrypt ciphertextbase64 to plaintext
 *
 * @param key the AES key in raw bytes (if key is 256 bits (32 bytes) then keybits should be ATCHOPS_AES_256)
 * @param keybits the AES key length in bits (e.g. AES-256 = 256 => ATCHOPS_AES_256)
 * @param iv the initialization vector (always 16 bytes long)
 * @param ciphertext the ciphertext in raw bytes
 * @param ciphertextlen the length of the ciphertext bytes buffer
 * @param plaintext the plaintext buffer to write to
 * @param plaintextsize the memory allocated length of the plaintext buffer
 * @param plaintextlen the written length of the plaintext buffer
 * @return int 0 on success
 */
int atchops_aesctr_decrypt(const unsigned char *key, const enum atchops_aes_size keybits,
                           unsigned char *iv, // always 16 bytes long
                           const unsigned char *ciphertext, const size_t ciphertextlen, unsigned char *plaintext,
                           const size_t plaintextsize, size_t *plaintextlen);

/**
 * @brief Used to calculate the length of the ciphertext buffer given the plaintext length. This is used when encrypting.
 *
 * @param plaintextlen the length of the plaintext string
 * @return a sufficient length of the ciphertext buffer
 */
size_t atchops_aesctr_ciphertext_size(const size_t plaintextlen);

/**
 * @brief Used to calculate the a sufficient buffer size of the plaintext buffer given the ciphertext length. This is used when decrypting.
 *
 * @param ciphertextlen the length of the ciphertext string
 * @return a sufficient length of the plaintext buffer
 */
size_t atchops_aesctr_plaintext_size(const size_t ciphertextlen);

#endif
