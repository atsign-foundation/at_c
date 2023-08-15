#pragma once

#include <string.h>
#include <stdint.h>
#include <stddef.h>

#define IV_AMOUNT_BYTES 16

typedef enum
{
    AES_128 = 128, // not tested
    AES_192 = 192,
    AES_256 = 256, // not tested
} AESKeySize;

int atchops_aes_ctr_encrypt(
    const char *keybase64,
    const unsigned long keybase64len,
    const AESKeySize keybits,
    const unsigned char *iv,
    const unsigned long ivlen,
    const unsigned char *plaintext,
    const unsigned long plaintextlen,
    unsigned char *ciphertextbase64,
    const unsigned long ciphertextbase64len,
    unsigned long *ciphertextbase64olen);

int atchops_aes_ctr_decrypt(
    const char *keybase64,
    const unsigned long keybase64len,
    const AESKeySize keybits,
    const unsigned char *iv,
    const unsigned long ivlen,
    const unsigned char *ciphertextbase64,
    const unsigned long ciphertextbase64len,
    unsigned char *plaintext,
    const size_t plaintextlen,
    unsigned long *plaintextolen);
