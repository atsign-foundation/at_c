#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <mbedtls/aes.h>
#include "atchops/aes_ctr.h"
#include "atchops/base64.h"

int atchops_aes_ctr_encrypt(
    const char *keybase64, 
    const unsigned long keybase64len,
    const AESKeySize keybits, 
    const unsigned char *iv,
    const unsigned long ivlen,
    const unsigned char *plaintext, // plaintext to encrypt 
    const unsigned long plaintextlen,  
    unsigned char *ciphertextbase64,  // buffer to populate
    const unsigned long ciphertextbase64len, // the size of the buffer
    unsigned long *ciphertextbase64olen // written actual length in the buffer
    )
{
    int ret = 1;

    // 1. initialize AES key
    unsigned long keylen = keybits/8;
    unsigned char *key = malloc(sizeof(unsigned char) * keylen);
    unsigned long keyolen;

    ret = atchops_base64_decode(key, keylen, &keyolen, keybase64, keybase64len);
    // printf("atchops_base64_decode: %d\n", ret);
    // printf("aes_key:\n");
    // for(int i = 0; i < keyolen; i++)
    // {
    //     printf("%02x ", *(key + i));
    // }
    // printf("\n\n");

    // 2. pad the plaintext
    unsigned char *plaintextpadded; // will contain the plaintext with padded trialing bytes
    size_t plaintextpaddedlen; // the length of the plain text + padding (no null terminator)

    const int num_pad_bytes_to_add = 16 - (plaintextlen % 16);
    const unsigned char padding_val = num_pad_bytes_to_add;
    // printf("appending %d bytes of padding: 0x%02x\n", num_pad_bytes_to_add, padding_val);

    plaintextpaddedlen = plaintextlen + num_pad_bytes_to_add;
    // printf("plaintext_paddedlen: %lu = %d + %d\n", plaintextpaddedlen, plaintextlen, num_pad_bytes_to_add);

    plaintextpadded = malloc(sizeof(unsigned char) * (plaintextpaddedlen + 1));
    memcpy(plaintextpadded, plaintext, plaintextlen);
    memset(plaintextpadded + plaintextlen, padding_val, num_pad_bytes_to_add);
    plaintextpadded[plaintextpaddedlen] = '\0';

    // printf("plaintext padded: %lu\n", plaintextpaddedlen);
    // for(int i = 0; i < plaintextpaddedlen + 1; i++) {
    //     printf("%.02x ", *(plaintextpadded + i));
    // }
    // printf("\n\n");

    // 3. AES CTR encrypt

    mbedtls_aes_context aes;

    mbedtls_aes_init(&aes);

    ret = mbedtls_aes_setkey_enc(&aes, key, keybits);
    // printf("mbedtls_aes_setkey_enc: %d\n", ret);

    unsigned long ciphertextlen = 5000;
    unsigned char *ciphertext = malloc(sizeof(unsigned char) * ciphertextlen);
    unsigned long ciphertextolen = 0;

    unsigned long nc_off = 0;
    unsigned char *stream_block = malloc(sizeof(unsigned char) * 16);
    memset(stream_block, 0, 16);

    ret = mbedtls_aes_crypt_ctr(&aes, plaintextpaddedlen, &nc_off, iv, stream_block, plaintextpadded, ciphertext);
    // printf("mbedtls_aes_crypt_ctr: %d\n", ret);

    free(stream_block);
    free(key);

    while(*(ciphertext + ciphertextolen++) != '\0');
    --ciphertextolen; // don't count the null terminator

    // printf("ciphertext after encryption (not base64 encoded yet): %lu\n", ciphertextolen);
    // for(int i = 0; i < ciphertextolen; i++)
    // {
    //     printf("%02x ", *(ciphertext + i));
    // }
    // printf("\n\n");

    // 4. base64 encode ciphertext

    ret = atchops_base64_encode(ciphertextbase64, ciphertextbase64len, ciphertextbase64olen, ciphertext, ciphertextolen);
    // printf("atchops_base64_encode: %d\n", ret);

    free(ciphertext);
    mbedtls_aes_free(&aes);

    return ret;
}

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
    unsigned long *plaintextolen
    )
{
    int ret = 1;

    // 1. initialize AES key
    unsigned long keylen = keybits/8;
    unsigned char *key = malloc(sizeof(unsigned char) * keylen);
    memset(key, 0, keylen);
    unsigned long keyolen = 0;

    ret = atchops_base64_decode(key, keylen, &keyolen, keybase64, keybase64len);
    // printf("atchops_base64_decode: %d\n", ret);
    // printf("aes_key: %lu\n", keyolen);
    // for(int i = 0; i < keyolen; i++)
    // {
    //     printf("%02x ", *(key + i));
    // }
    // printf("\n\n");

    // 2. decode the ciphertextbase64 into ciphertext
    unsigned long ciphertextlen = 5000;
    unsigned char *ciphertext = malloc(sizeof(unsigned char) * ciphertextlen);
    memset(ciphertext, 0, ciphertextlen);
    unsigned long ciphertextolen = 0;

    // printf("ciphertextbase64: %lu | %.*s\n", ciphertextbase64len, ciphertextbase64len, ciphertextbase64);
    // for(int i = 0; i < ciphertextbase64len; i++)
    // {
    //     printf("%02x ", *(ciphertextbase64 + i));
    // }
    // printf("\n\n");
    ret = atchops_base64_decode(ciphertext, ciphertextlen, &ciphertextolen, ciphertextbase64, ciphertextbase64len);
    // printf("atchops_base64_decode: %d\n", ret);
    // printf("ciphertext decoded: %lu\n", ciphertextolen);
    // for(int i = 0; i < ciphertextolen; i++)
    // {
    //     printf("%02x ", *(ciphertext + i));
    // }
    // printf("\n\n");

    // 3. AES decrypt
    mbedtls_aes_context aes;
    mbedtls_aes_init(&aes);

    ret = mbedtls_aes_setkey_enc(&aes, key, keybits);
    // printf("mbedtls_aes_setkey_enc: %d\n", ret);

    unsigned long nc_off = 0;
    unsigned char *stream_block = malloc(sizeof(unsigned char) * 16);
    memset(stream_block, 0, 16);

    unsigned long plaintextpaddedlen = 1000;
    unsigned char *plaintextpadded = malloc(sizeof(unsigned char) * plaintextpaddedlen);
    memset(plaintextpadded, 0, plaintextpaddedlen);
    unsigned long plaintextpaddedolen = 0;

    ret = mbedtls_aes_crypt_ctr(&aes, ciphertextolen, &nc_off, iv, stream_block, ciphertext, plaintextpadded);
    // printf("mbedtls_aes_crypt_ctr: %d\n", ret);

    // printf("plaintextpadded: %.*s\n", plaintextpaddedlen, plaintextpadded);
    // for(int i = 0; i < plaintextpaddedlen; i++)
    // {
    //     printf("%02x ", *(plaintextpadded + i));
    // }
    // printf("\n\n");

    while(*(plaintextpadded + plaintextpaddedolen++) != '\0');
    --plaintextpaddedolen; // don't count the null terminator

    // printf("plaintextpadded: %lu | %.*s\n", plaintextpaddedolen, plaintextpaddedolen, plaintextpadded);
    // for(int i = 0; i < plaintextpaddedolen; i++)
    // {
    //     printf("%02x ", *(plaintextpadded + i));
    // }
    // printf("\n\n");

    free(stream_block);
    free(key);

    // 4. remove padding

    // IBM PKCS Padding method states that there is always at least 1 padded value: https://www.ibm.com/docs/en/zos/2.4.0?topic=rules-pkcs-padding-method
    // the value of the padded byte is always the number of padded bytes to expect, pad_val == num_padded_bytes
    unsigned char pad_val = *(plaintextpadded + (plaintextpaddedolen - 1));
    // printf("pad_val byte: 0x%02x\n", pad_val);


    // add null terminator for good sake
    *(plaintextpadded + plaintextpaddedolen - pad_val) = '\0';


    *plaintextolen = plaintextpaddedolen - pad_val;
    memcpy(plaintext, plaintextpadded, *plaintextolen);

    // free everything
    free(ciphertext);
    mbedtls_aes_free(&aes);

    return ret;
}