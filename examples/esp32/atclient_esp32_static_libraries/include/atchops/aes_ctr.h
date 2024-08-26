#ifndef ATCHOPS_AES_CTR_H
#define ATCHOPS_AES_CTR_H

#include "atchops/aes.h"
#include <stddef.h>

/**
 * @brief AES CTR encrypt plaintext to ciphertextbase64 (base64 encoded string)
 *
 * @param key the AES key in raw bytes (if key is 256 bits (32 bytes) then key_bits should be ATCHOPS_AES_256)
 * @param key_bits the AES key length in bits (e.g. AES-256 = 256 => ATCHOPS_AES_256)
 * @param iv the initialization vector (always 16 bytes long)
 * @param plaintext the plaintext to encrypt
 * @param plaintext_len the length of the plaintext string
 * @param ciphertext the ciphertext buffer to write to
 * @param ciphertext_size the memory allocated length of the ciphertext buffer
 * @param ciphertext_len the written length of the ciphertext buffer
 * @return int 0 on success
 */
int atchops_aes_ctr_encrypt(const unsigned char *key, const enum atchops_aes_size key_bits,
                           unsigned char *iv, // always 16 bytes long
                           const unsigned char *plaintext, const size_t plaintext_len, unsigned char *ciphertext,
                           const size_t ciphertext_size, size_t *ciphertext_len);

/**
 * @brief AES CTR decrypt ciphertextbase64 to plaintext
 *
 * @param key the AES key in raw bytes (if key is 256 bits (32 bytes) then key_bits should be ATCHOPS_AES_256)
 * @param key_bits the AES key length in bits (e.g. AES-256 = 256 => ATCHOPS_AES_256)
 * @param iv the initialization vector (always 16 bytes long)
 * @param ciphertext the ciphertext in raw bytes
 * @param ciphertext_len the length of the ciphertext bytes buffer
 * @param plaintext the plaintext buffer to write to
 * @param plaintextsize the memory allocated length of the plaintext buffer
 * @param plaintext_len the written length of the plaintext buffer
 * @return int 0 on success
 */
int atchops_aes_ctr_decrypt(const unsigned char *key, const enum atchops_aes_size key_bits,
                           unsigned char *iv, // always 16 bytes long
                           const unsigned char *ciphertext, const size_t ciphertext_len, unsigned char *plaintext,
                           const size_t plaintextsize, size_t *plaintext_len);

/**
 * @brief Used to calculate the length of the ciphertext buffer given the plaintext length. This is used when encrypting.
 *
 * @param plaintext_len the length of the plaintext string
 * @return a sufficient length of the ciphertext buffer
 */
size_t atchops_aes_ctr_ciphertext_size(const size_t plaintext_len);

/**
 * @brief Used to calculate the a sufficient buffer size of the plaintext buffer given the ciphertext length. This is used when decrypting.
 *
 * @param ciphertext_len the length of the ciphertext string
 * @return a sufficient length of the plaintext buffer
 */
size_t atchops_aes_ctr_plaintext_size(const size_t ciphertext_len);

#endif
