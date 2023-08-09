#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <mbedtls/aes.h>
#include "atchops/aes_ctr.h"
#include "atchops/base64.h"

#define AES_KEY_BITS 256
#define AES_KEY_BYTES AES_KEY_BITS / 8
#define IV_AMOUNT_BYTES 16

#define MAX_BYTES_ALLOCATED_FOR_ENCRYPTION_OPERATION 5000

int atchops_aes_ctr_encrypt(const char *key_base64, const AESKeySize key_size, const unsigned char *plaintext, const size_t plaintextlen, size_t *ciphertextolen, unsigned char *ciphertext, const size_t ciphertextlen)
{
    int ret = 1;
    size_t plaintext_len = strlen(plaintext);

    // pad the plain text to be a multiple of 16 bytes
    // printf("Padding...\n");
    unsigned char *plaintext_padded;
    size_t plaintext_paddedlen;

    const short int mod = plaintext_len % 16;
    const short int num_pad_bytes_to_add = 16 - mod;
    const unsigned char padding_val = num_pad_bytes_to_add;

    plaintext_paddedlen = plaintext_len + num_pad_bytes_to_add;
    // printf("plaintext_paddedlen: %lu = %d + %d\n", plaintext_paddedlen, len, num_pad_bytes_to_add);
    plaintext_padded = malloc(sizeof(unsigned char) * (plaintext_paddedlen + 1));
    for (int i = 0; i < plaintext_len; i++)
    {
        // printf("ia: %d\n", i);
        *(plaintext_padded + i) = *(plaintext + i);
    }
    for (int i = plaintext_len; i < plaintext_len + num_pad_bytes_to_add; i++)
    {
        *(plaintext_padded + i) = padding_val;
        // printf("ib: %d\n", i);
    }

    // printf("Plaintext Padded: \"%s\"\n", plaintext_padded);

    // initialize AES key
    unsigned char key[key_size/8];
    size_t keylen = sizeof(key);
    size_t *writtenlen = malloc(sizeof(size_t));

    ret = atchops_base64_decode(key, keylen, writtenlen, key_base64, strlen(key_base64));

    // initialize AES context
    mbedtls_aes_context *ctx = malloc(sizeof(mbedtls_aes_context));
    mbedtls_aes_init(ctx);
    ret = mbedtls_aes_setkey_enc(ctx, key, key_size);

    size_t *iv_ctr = malloc(sizeof(unsigned int));
    unsigned char *iv = malloc(sizeof(unsigned char) * IV_AMOUNT_BYTES);
    unsigned char *stream_block = malloc(sizeof(unsigned char) * IV_AMOUNT_BYTES);
    unsigned char *aes_encrypted = malloc(sizeof(unsigned char) * MAX_BYTES_ALLOCATED_FOR_ENCRYPTION_OPERATION);

    // maybe base 64 encode it before feeding to cipher

    // run encrypt
    ret = mbedtls_aes_crypt_ctr(ctx, plaintext_paddedlen, iv_ctr, iv, stream_block, plaintext_padded, aes_encrypted);

    // find how much of the encrypted data is actually used
    int aes_encryptedlen = 0;
    unsigned char byte;
    do
    {
        byte = *(aes_encrypted + aes_encryptedlen++);
        // printf("%x\n", byte);
    } while (byte != 0);
    --aes_encryptedlen;

    // encode the encrypted data in base64
    size_t dstlen = MAX_TEXT_LENGTH_FORBASE64_ENCODING_OPERATION;
    unsigned char *dst = malloc(sizeof(unsigned char) * dstlen);
    ret = atchops_base64_encode(dst, dstlen, writtenlen, aes_encrypted, aes_encryptedlen);

    // printf("%s\n", dst);

    // done
    unsigned char *p = ciphertext;
    for (int i = 0; i < ciphertextlen; i++)
    {
        *p++ = *(dst + i);
    }
    *ciphertextolen = *writtenlen;

    mbedtls_aes_free(ctx);
    free(iv_ctr);
    free(iv);
    free(stream_block);
    free(aes_encrypted);

    return ret;
}

int atchops_aes_ctr_decrypt(const char *key_base64, const AESKeySize key_size, const unsigned char *ciphertext, const size_t ciphertextlen, size_t *plaintextolen, unsigned char *plaintext, const size_t plaintextlen)
{
    int ret = 1;
    // initialize AES key

    unsigned char key[key_size/8];
    size_t keylen = sizeof(key);

    size_t *writtenlen = malloc(sizeof(size_t));
    ret = atchops_base64_decode(key, keylen, writtenlen, key_base64, strlen(key_base64));

    // initialize AES context
    mbedtls_aes_context *ctx = malloc(sizeof(mbedtls_aes_context));
    mbedtls_aes_init(ctx);
    ret = mbedtls_aes_setkey_enc(ctx, key, key_size);

    // decode the base64 ciphertext
    size_t dstlen = MAX_TEXT_LENGTH_FORBASE64_ENCODING_OPERATION;
    unsigned char *dst = malloc(sizeof(unsigned char) * dstlen);
    ret = atchops_base64_decode(dst, dstlen, writtenlen, ciphertext, strlen(ciphertext));

    // run decrypt
    size_t *iv_ctr = malloc(sizeof(unsigned int));
    unsigned char *iv = malloc(sizeof(unsigned char) * IV_AMOUNT_BYTES);
    unsigned char *stream_block = malloc(sizeof(unsigned char) * IV_AMOUNT_BYTES);
    unsigned char *aes_decrypted = malloc(sizeof(unsigned char) * MAX_BYTES_ALLOCATED_FOR_ENCRYPTION_OPERATION);

    ret = mbedtls_aes_crypt_ctr(ctx, *writtenlen, iv_ctr, iv, stream_block, dst, aes_decrypted);

    // find how much of the decrypted data is actually used
    int aes_decryptedlen = 0;
    unsigned char byte;
    do
    {
        byte = *(aes_decrypted + aes_decryptedlen++);
        // printf("%x\n", byte);
    } while (byte != '\0');

    // remove padding

    // find the value of the pad
    unsigned char pad_val = *(aes_decrypted + aes_decryptedlen - 2);
    // printf("pad_val: %02x\n", pad_val);
    if(pad_val >= 0x00 && pad_val <= 0x0F || pad_val == 0x10) // https://www.ibm.com/docs/en/zos/2.4.0?topic=rules-pkcs-padding-method
    {
        // eliminate that amount of padding
        aes_decryptedlen -= (pad_val+1);
        *(aes_decrypted+aes_decryptedlen) = '\0';
    }

    // printf("aa\n");
    // for(int i = 0; i < aes_decryptedlen + 10; i++)
    // {
    //     printf("%02x ", *(aes_decrypted+i));
    // }
    // printf("aa\n");

    unsigned char *aes_decrypted_unpadded = malloc(sizeof(unsigned char) * aes_decryptedlen);
    for (int i = 0; i < aes_decryptedlen; i++)
    {
        *(aes_decrypted_unpadded + i) = *(aes_decrypted + i);
    }

    // done
    unsigned char *p = plaintext;
    for (int i = 0; i < plaintextlen; i++)
    {
        *p++ = *(aes_decrypted_unpadded + i);
    }
    *plaintextolen = aes_decryptedlen;

    mbedtls_aes_free(ctx);
    free(iv_ctr);
    free(iv);
    free(stream_block);
    free(aes_decrypted);

    return ret;
}
