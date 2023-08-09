#pragma once

#include <string.h>

#define IV_AMOUNT_BYTES 16

typedef enum {
    AES_128 = 128,
    AES_192 = 192,
    AES_256 = 256,
} AESKeySize;

/**
 * @brief AES CTR encrypt plaintext
 * 
 * @param key_base64 the base64 encoded AES 256 key (e.g. "1DPU9OP3CYvamnVBMwGgL7fm8yB1klAap0Uc5Z9R79g=")
 * @param plaintext the plain text to encryt, must be null terminated `\0`
 * @return AESResult* the result of the encryption
 */
int atchops_aes_ctr_encrypt(const char *key_base64, const AESKeySize key_size, const unsigned char *plaintext, const size_t plaintextlen, size_t *ciphertextolen, unsigned char *ciphertext, const size_t ciphertextlen);

/**
 * @brief AES CTR decrypt cipher text
 * 
 * @param key_base64 the base64 encoded AES 256 key (e.g. "1DPU9OP3CYvamnVBMwGgL7fm8yB1klAap0Uc5Z9R79g=")
 * @param ciphertext the base64 encoded cipher text, must be null terminated `\0`
 * @return AESResult* the result of the decrytion
 */
int atchops_aes_ctr_decrypt(const char *key_base64, const AESKeySize key_size, const unsigned char *ciphertext, const size_t ciphertextlen, size_t *plaintextolen, unsigned char *plaintext, const size_t plaintextlen);
