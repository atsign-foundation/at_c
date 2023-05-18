#pragma once

#ifdef BUILD_MBEDTLS
#ifdef __cplusplus
extern "C"
{
#endif

#include <string.h>

typedef struct {
    unsigned char *res; // result of the encryption/decryption
    size_t reslen; // length of the result written
} AESResult;

/**
 * @brief AES 256 CTR encrypt plaintext
 * 
 * @param key_base64 the base64 encoded AES 256 key (e.g. "1DPU9OP3CYvamnVBMwGgL7fm8yB1klAap0Uc5Z9R79g=")
 * @param plaintext the plain text to encryt, must be null terminated `\0`
 * @return AESResult* the result of the encryption
 */
AESResult *atchops_aes256ctr_encrypt(const char *key_base64, const unsigned char *plaintext);

/**
 * @brief AES 256 CTR decrypt cipher text
 * 
 * @param key_base64 the base64 encoded AES 256 key (e.g. "1DPU9OP3CYvamnVBMwGgL7fm8yB1klAap0Uc5Z9R79g=")
 * @param ciphertext the base64 encoded cipher text, must be null terminated `\0`
 * @return AESResult* the result of the decrytion
 */
AESResult *atchops_aes256ctr_decrypt(const char *key_base64, const unsigned char *ciphertext);

#ifdef __cplusplus
}
#endif
#endif