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

int atchops_aes_ctr_encrypt(const char *key_base64, const AESKeySize key_size, const unsigned char *plaintext, const unsigned long plaintextlen, unsigned long *ciphertextbase64olen, unsigned char *ciphertextbase64, const unsigned long ciphertextbase64len)
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
    printf("plaintext_paddedlen: %lu = %d + %d\n", plaintext_paddedlen, plaintext_len, num_pad_bytes_to_add);
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
    printf("plaintext padded: %lu\n", plaintext_paddedlen);
    for(int i = 0; i < plaintextlen + plaintext_paddedlen+7; i++) {
        printf("%.02x ", *(plaintext_padded + i));
    }
    printf("\n");

    printf("\ninitializing aes key....\n");
    // initialize AES key
    unsigned char key[256/8] = {0};
    size_t keylen = sizeof(key);
    size_t *writtenlen = malloc(sizeof(size_t));

    ret = atchops_base64_decode(key, keylen, writtenlen, key_base64, strlen(key_base64));
    printf("atchops_base64_decode: %d\n", ret);

    printf("key: %lu %lu\n", keylen, *writtenlen);
    for(int i = 0; i < keylen+15; i++) {
        printf("%.02x ", *(key + i));
    }
    printf("\n");

    // key is ready

    psa_status_t status;
    psa_key_attributes_t attributes = PSA_KEY_ATTRIBUTES_INIT;
    psa_key_id_t psa_key = 0;
    size_t output_len = 0;
    const size_t block_size = 16;
    uint8_t iv[block_size] = {0};

    status = psa_crypto_init();
    printf("psa_crypto_init: %d\n", status);

    psa_set_key_usage_flags(&attributes, PSA_KEY_USAGE_ENCRYPT);
    psa_set_key_algorithm(&attributes, PSA_ALG_CTR);
    psa_set_key_type(&attributes, PSA_KEY_TYPE_AES);
    psa_set_key_bits(&attributes, 256);

    status = psa_import_key(&attributes, key, 32, &psa_key);
    printf("psa_import_key: %d\n", status);
    if (status != PSA_SUCCESS) {
        printf("Failed to import a key\n");
        return status;
    }

    unsigned char *ciphertext_notencoded = malloc(sizeof(unsigned char) * 5000);
    unsigned long *ciphertext_notencodedolen = malloc(sizeof(unsigned long));

    status = psa_cipher_encrypt(psa_key, PSA_ALG_CTR, plaintext_padded, plaintext_paddedlen, ciphertext_notencoded, 5000, ciphertext_notencodedolen);
    printf("psa_cipher_encrypt: %d\n", status);

    for(int i = 0; i < *ciphertext_notencodedolen+15; i++) {
        printf("%.02x ", *(ciphertext_notencoded + i));
    }
    printf("\n");

    // initialize AES context
    // mbedtls_aes_context *ctx = malloc(sizeof(mbedtls_aes_context));
    // mbedtls_aes_init(ctx);
    // ret = mbedtls_aes_setkey_enc(ctx, key, key_size);

    // size_t *iv_ctr = malloc(sizeof(unsigned int));
    // *iv_ctr = 0;
    // unsigned char *iv = malloc(sizeof(unsigned char) * 16);
    // memset(iv, 0, 16);
    // unsigned char *stream_block = malloc(sizeof(unsigned char) * 16);
    // memset(stream_block, 0, 16);
    // unsigned char *aes_encrypted = malloc(sizeof(unsigned char) * 5000);
    // memset(aes_encrypted, 0, 5000);

    // // maybe base 64 encode it before feeding to cipher

    // // run encrypt
    // ret = mbedtls_aes_crypt_ctr(ctx, plaintext_paddedlen, iv_ctr, iv, stream_block, plaintext_padded, aes_encrypted);

    // // find how much of the encrypted data is actually used
    // int aes_encryptedlen = 0;
    // unsigned char byte;
    // do
    // {
    //     byte = *(aes_encrypted + aes_encryptedlen++);
    //     // printf("%x\n", byte);
    // } while (byte != 0);
    // aes_encryptedlen = aes_encryptedlen - 1;

    // encode the encrypted data in base64
    size_t dstlen = MAX_TEXT_LENGTH_FORBASE64_ENCODING_OPERATION;
    unsigned char *dst = malloc(sizeof(unsigned char) * dstlen);
    ret = atchops_base64_encode(dst, dstlen, writtenlen, ciphertext_notencoded, *ciphertext_notencodedolen);

    // printf("%s\n", dst);

    // done
    unsigned char *p = ciphertextbase64;
    for (int i = 0; i < *writtenlen; i++)
    {
        *p++ = *(dst + i);
    }
    *ciphertextbase64olen = *writtenlen;

    // mbedtls_aes_free(ctx);
    // free(iv_ctr);
    // free(iv);
    // free(stream_block);
    // free(aes_encrypted);

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
    // mbedtls_aes_context *ctx = malloc(sizeof(mbedtls_aes_context));
    // mbedtls_aes_init(ctx);
    // ret = mbedtls_aes_setkey_enc(ctx, key, key_size);

    // decode the base64 ciphertext
    size_t dstlen = MAX_TEXT_LENGTH_FORBASE64_ENCODING_OPERATION;
    unsigned char *dst = malloc(sizeof(unsigned char) * dstlen);
    ret = atchops_base64_decode(dst, dstlen, writtenlen, ciphertext, strlen(ciphertext));

    printf("\nDecoded ciphertext: %lu\n", *writtenlen);
    for(int i = 0; i < *writtenlen+16; i++) {
        printf("%.2x ", *(dst + i));
    }
    printf("\n");

    // run decrypt

    psa_crypto_init();

    psa_key_attributes_t attributes = PSA_KEY_ATTRIBUTES_INIT;
    psa_key_id_t psa_key = 0;
    size_t output_len = 0;

    psa_set_key_algorithm(&attributes, PSA_ALG_CTR);
    psa_set_key_type(&attributes, PSA_KEY_TYPE_AES);
    psa_set_key_bits(&attributes, key_size);
    psa_set_key_usage_flags(&attributes, PSA_KEY_USAGE_DECRYPT);

    psa_status_t status = psa_import_key(&attributes, key, key_size/8, &psa_key);
    printf("psa_import_key: %d\n", status);

    psa_cipher_decrypt(psa_key, PSA_ALG_CTR, dst, *writtenlen, plaintext, plaintextlen, plaintextolen);

    // size_t *iv_ctr = malloc(sizeof(unsigned int));
    // *iv_ctr = 0;
    // unsigned char *iv = malloc(sizeof(unsigned char) * IV_AMOUNT_BYTES);
    // memset(iv, 0, IV_AMOUNT_BYTES);
    // unsigned char *stream_block = malloc(sizeof(unsigned char) * IV_AMOUNT_BYTES);
    // memset(stream_block, 0, IV_AMOUNT_BYTES);
    // unsigned char *aes_decrypted = malloc(sizeof(unsigned char) * MAX_BYTES_ALLOCATED_FOR_ENCRYPTION_OPERATION);
    // memset(aes_decrypted, 0, MAX_BYTES_ALLOCATED_FOR_ENCRYPTION_OPERATION);

    // ret = mbedtls_aes_crypt_ctr(ctx, *writtenlen, iv_ctr, iv, stream_block, dst, aes_decrypted);

    // // find how much of the decrypted data is actually used
    // int aes_decryptedlen = 0;
    // unsigned char byte;
    // printf("\nFinding out how much of the encrypted data is actually used: \n");
    // do
    // {
    //     byte = *(aes_decrypted + aes_decryptedlen++);
    //     printf("%.2x ", byte);
    // } while (byte != '\0');
    // printf("\n");

    // // remove padding

    // // find the value of the pad
    // unsigned char pad_val = *(aes_decrypted + aes_decryptedlen - 2);
    // // printf("pad_val: %02x\n", pad_val);
    // if(pad_val >= 0x00 && pad_val <= 0x0F || pad_val == 0x10) // https://www.ibm.com/docs/en/zos/2.4.0?topic=rules-pkcs-padding-method
    // {
    //     // eliminate that amount of padding
    //     aes_decryptedlen -= (pad_val+1);
    //     *(aes_decrypted+aes_decryptedlen) = '\0';
    // }

    // // printf("aa\n");
    // // for(int i = 0; i < aes_decryptedlen + 10; i++)
    // // {
    // //     printf("%02x ", *(aes_decrypted+i));
    // // }
    // // printf("aa\n");

    // unsigned char *aes_decrypted_unpadded = malloc(sizeof(unsigned char) * aes_decryptedlen);
    // for (int i = 0; i < aes_decryptedlen; i++)
    // {
    //     *(aes_decrypted_unpadded + i) = *(aes_decrypted + i);
    // }

    // // done
    // unsigned char *p = plaintext;
    // for (int i = 0; i < plaintextlen; i++)
    // {
    //     *p++ = *(aes_decrypted_unpadded + i);
    // }
    // *plaintextolen = aes_decryptedlen;

    // mbedtls_aes_free(ctx);
    // free(iv_ctr);
    // free(iv);
    // free(stream_block);
    // free(aes_decrypted);

    return ret;
}
