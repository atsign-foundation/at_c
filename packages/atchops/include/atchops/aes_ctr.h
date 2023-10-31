#ifndef ATCHOPS_AES_CTR_H
#define ATCHOPS_AES_CTR_H

typedef enum atchops_aes_keysize {
    ATCHOPS_AES_128 = 128, // not tested
    ATCHOPS_AES_256 = 256,
} atchops_aes_keysize;

int atchops_aes_ctr_encrypt(
    const char *keybase64,
    const unsigned long keybase64len,
    const atchops_aes_keysize keybits,
    unsigned char *iv, // always 16 bytes long
    const unsigned char *plaintext,
    const unsigned long plaintextlen,
    unsigned char *ciphertextbase64,
    const unsigned long ciphertextbase64len,
    unsigned long *ciphertextbase64olen);

int atchops_aes_ctr_decrypt(
    const char *keybase64,
    const unsigned long keybase64len,
    const atchops_aes_keysize keybits,
    unsigned char *iv, // always 16 bytes long
    const unsigned char *ciphertextbase64,
    const unsigned long ciphertextbase64len,
    unsigned char *plaintext,
    const unsigned long plaintextlen,
    unsigned long *plaintextolen);

int atchops_aes_ctr_generate_keybase64(unsigned char *keybase64, const unsigned long keybase64len, unsigned long *keybase64olen, atchops_aes_keysize keylen);

#endif