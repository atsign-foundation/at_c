#pragma once

typedef enum atchops_aes_keysize {
    ATCHOPS_AES_128 = 128, // not tested
    ATCHOPS_AES_192 = 192, // not tested
    ATCHOPS_AES_256 = 256,
} atchops_aes_keysize;

int atchops_aes_ctr_encrypt(
    const char *keybase64,
    const unsigned long keybase64len,
    const atchops_aes_keysize keybits,
    const unsigned char *iv, // always length 16 bytes
    const unsigned char *plaintext,
    const unsigned long plaintextlen,
    unsigned char *ciphertextbase64,
    const unsigned long ciphertextbase64len,
    unsigned long *ciphertextbase64olen);

int atchops_aes_ctr_decrypt(
    const char *keybase64,
    const unsigned long keybase64len,
    const atchops_aes_keysize keybits,
    const unsigned char *iv, // always length 16 bytes
    const unsigned char *ciphertextbase64,
    const unsigned long ciphertextbase64len,
    unsigned char *plaintext,
    const unsigned long plaintextlen,
    unsigned long *plaintextolen);
