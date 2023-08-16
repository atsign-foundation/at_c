#pragma once

typedef enum AESKeySize {
    AES_128 = 128, // not tested
    AES_192 = 192, // not tested
    AES_256 = 256,
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
    const unsigned long plaintextlen,
    unsigned long *plaintextolen);
