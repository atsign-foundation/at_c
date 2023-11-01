#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <mbedtls/aes.h>
#include <mbedtls/entropy.h>
#include <mbedtls/ctr_drbg.h>
#include "atchops/aesctr.h"
#include "atchops/base64.h"
#include "atchops/constants.h"

int atchops_aesctr_encrypt(
    const char *keybase64,
    const unsigned long keybase64len,
    const atchops_aes_keysize keybits,
    unsigned char *iv,
    const unsigned char *plaintext, // plaintext to encrypt
    const unsigned long plaintextlen,
    unsigned char *ciphertextbase64,         // buffer to populate
    const unsigned long ciphertextbase64len, // the size of the buffer
    unsigned long *ciphertextbase64olen      // written actual length in the buffer
)
{
    int ret = 1;

    // 1. initialize AES key
    const unsigned long keylen = keybits / 8; // 256/8 = 32 bytes long
    unsigned char *key = malloc(sizeof(unsigned char) * keylen);
    unsigned long keyolen = 0;

    ret = atchops_base64_decode((const unsigned char *)keybase64, keybase64len, key, keylen, &keyolen);
    // printf("atchops_base64_decode: %d\n", ret);
    if (ret != 0)
    {
        goto exit;
    }

    // 2. pad the plaintext
    unsigned char *plaintextpadded;   // will contain the plaintext with padded trialing bytes
    unsigned long plaintextpaddedlen; // the length of the plain text + padding (no null terminator)

    const int numpadbytestoadd = 16 - (plaintextlen % 16);
    const unsigned char padval = numpadbytestoadd;
    // printf("appending %d bytes of padding: 0x%02x\n", numpadbytestoadd, padval);

    plaintextpaddedlen = plaintextlen + numpadbytestoadd;
    // printf("plaintext_paddedlen: %lu = %d + %d\n", plaintextpaddedlen, plaintextlen, numpadbytestoadd);

    plaintextpadded = malloc(sizeof(unsigned char) * (plaintextpaddedlen + 1));
    memcpy(plaintextpadded, plaintext, plaintextlen);
    memset(plaintextpadded + plaintextlen, padval, numpadbytestoadd);
    plaintextpadded[plaintextpaddedlen] = '\0';

    // 3. AES CTR encrypt
    mbedtls_aes_context aes;
    mbedtls_aes_init(&aes);

    ret = mbedtls_aes_setkey_enc(&aes, key, keybits);
    // printf("mbedtls_aes_setkey_enc: %d\n", ret);
    if (ret != 0)
    {
        goto exit;
    }

    const unsigned long ciphertextlen = plaintextlen * 8; // 8 times the plaintext length should be sufficient space for the ciphertext
    unsigned char *ciphertext = malloc(sizeof(unsigned char) * ciphertextlen);
    memset(ciphertext, 0, ciphertextlen);
    unsigned long ciphertextolen = 0;

    unsigned long nc_off = 0;
    unsigned char *stream_block = malloc(sizeof(unsigned char) * 16);
    memset(stream_block, 0, 16);

    ret = mbedtls_aes_crypt_ctr(&aes, plaintextpaddedlen, &nc_off, iv, stream_block, plaintextpadded, ciphertext);
    // printf("mbedtls_aes_crypt_ctr: %d\n", ret);
    if (ret != 0)
    {
        goto exit;
    }

    while (*(ciphertext + ciphertextolen++) != '\0')
        ;
    --ciphertextolen; // don't count the null terminator

    // 4. base64 encode ciphertext
    ret = atchops_base64_encode(ciphertext, ciphertextolen, ciphertextbase64, ciphertextbase64len, ciphertextbase64olen);
    // printf("atchops_base64_encode: %d\n", ret);
    if (ret != 0)
    {
        goto exit;
    }

    goto exit;

exit:
{
    free(stream_block);
    free(key);
    free(ciphertext);
    mbedtls_aes_free(&aes);
    return ret;
}
}

int atchops_aesctr_decrypt(
    const char *keybase64,
    const unsigned long keybase64len,
    const atchops_aes_keysize keybits,
    unsigned char *iv,
    const unsigned char *ciphertextbase64,
    const unsigned long ciphertextbase64len,
    unsigned char *plaintext,
    const unsigned long plaintextlen,
    unsigned long *plaintextolen)
{
    int ret = 1;

    // 1. initialize AES key
    unsigned long keylen = keybits / 8;
    unsigned char *key = malloc(sizeof(unsigned char) * keylen);
    memset(key, 0, keylen);
    unsigned long keyolen = 0;

    ret = atchops_base64_decode((const unsigned char *)keybase64, keybase64len, key, keylen, &keyolen);
    // printf("atchops_base64_decode: %d\n", ret);
    if (ret != 0)
    {
        goto exit;
    }

    // 2. decode the ciphertextbase64 into ciphertext
    unsigned long ciphertextlen = ciphertextbase64len; // length of base64 should be greater than decoded text
    unsigned char *ciphertext = malloc(sizeof(unsigned char) * ciphertextlen);
    memset(ciphertext, 0, ciphertextlen);
    unsigned long ciphertextolen = 0;

    ret = atchops_base64_decode(ciphertextbase64, ciphertextbase64len, ciphertext, ciphertextlen, &ciphertextolen);
    // printf("atchops_base64_decode: %d\n", ret);
    if (ret != 0)
    {
        goto exit;
    }

    // 3. AES decrypt
    mbedtls_aes_context aes;
    mbedtls_aes_init(&aes);

    ret = mbedtls_aes_setkey_enc(&aes, key, keybits);
    // printf("mbedtls_aes_setkey_enc: %d\n", ret);
    if (ret != 0)
    {
        goto exit;
    }

    unsigned long nc_off = 0;
    unsigned char *stream_block = malloc(sizeof(unsigned char) * 16);
    memset(stream_block, 0, 16);

    unsigned long plaintextpaddedlen = plaintextlen;
    unsigned char *plaintextpadded = malloc(sizeof(unsigned char) * plaintextpaddedlen);
    memset(plaintextpadded, 0, plaintextpaddedlen);
    unsigned long plaintextpaddedolen = 0;

    ret = mbedtls_aes_crypt_ctr(&aes, ciphertextolen, &nc_off, iv, stream_block, ciphertext, plaintextpadded);
    // printf("mbedtls_aes_crypt_ctr: %d\n", ret);
    if (ret != 0)
    {
        goto exit;
    }

    while (*(plaintextpadded + plaintextpaddedolen++) != '\0')
        ;
    --plaintextpaddedolen; // don't count the null terminator

    // 4. remove padding

    // IBM PKCS Padding method states that there is always at least 1 padded value: https://www.ibm.com/docs/en/zos/2.4.0?topic=rules-pkcs-padding-method
    // the value of the padded byte is always the number of padded bytes to expect, padval == num_padded_bytes
    unsigned char padval = *(plaintextpadded + (plaintextpaddedolen - 1));
    // printf("padval byte: 0x%02x\n", padval);

    // add null terminator for good sake
    *(plaintextpadded + plaintextpaddedolen - padval) = '\0';

    *plaintextolen = plaintextpaddedolen - padval;
    memcpy(plaintext, plaintextpadded, *plaintextolen);

    goto exit;

exit:
{

    // free everything
    free(key);
    free(stream_block);
    free(ciphertext);
    free(plaintextpadded);
    mbedtls_aes_free(&aes);

    return ret;
}
}