#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <mbedtls/rsa.h>
#include <mbedtls/asn1.h>
#include <mbedtls/md5.h>
#include <mbedtls/entropy.h>
#include <mbedtls/ctr_drbg.h>
#include "atchops/rsa.h"
#include "atchops/rsakey.h"
#include "atchops/base64.h"
#include "atchops/sha.h"

int atchops_rsa_sign(atchops_rsakey_privatekey privatekey, atchops_md_type mdtype, const unsigned char *message, const unsigned long messagelen, unsigned char *signaturebase64, const unsigned long signaturebase64len, unsigned long *signaturebase64olen)
{
    int ret = 1; // error, until successful.

    // 1. hash the message

    const unsigned long hashlen = 32;
    unsigned char *hash = malloc(sizeof(unsigned char) * hashlen);
    memset(hash, 0, hashlen);
    unsigned long hasholen = 0;

    ret = atchops_sha_hash(mdtype, message, messagelen, hash, hashlen, &hasholen);
    // printf("atchops_sha_hash: %d\n", ret);
    if (ret != 0)
    {
        goto ret;
    }

    // 2. sign the hash with rsa private key

    mbedtls_rsa_context rsa;
    mbedtls_rsa_init(&rsa);

    ret = mbedtls_rsa_import_raw(&rsa,
                                 privatekey.n.value, privatekey.n.len,
                                 privatekey.p.value, privatekey.p.len,
                                 privatekey.q.value, privatekey.q.len,
                                 privatekey.d.value, privatekey.d.len,
                                 privatekey.e.value, privatekey.e.len);
    // printf("rsa import: %d\n", ret);
    if (ret != 0)
    {
        goto ret;
    }

    ret = mbedtls_rsa_complete(&rsa);
    // printf("rsa complete: %d\n", ret);
    if (ret != 0)
    {
        goto ret;
    }

    ret = mbedtls_rsa_check_privkey(&rsa);
    // printf("rsa check privkey: %d\n", ret);
    if (ret != 0)
    {
        goto ret;
    }

    mbedtls_entropy_context entropy_ctx;
    mbedtls_entropy_init(&entropy_ctx);

    mbedtls_ctr_drbg_context ctr_drbg_ctx;
    mbedtls_ctr_drbg_init(&ctr_drbg_ctx);
    ret = mbedtls_ctr_drbg_seed(&ctr_drbg_ctx, mbedtls_entropy_func, &entropy_ctx, NULL, 0);
    // printf("mbedtls_ctr_drbg_seed: %d\n", ret);
    if (ret != 0)
    {
        goto ret;
    }

    const unsigned long signaturelen = 256; // result of signature always 256 bytes
    unsigned char *signature = malloc(sizeof(unsigned char) * signaturelen);
    memset(signature, 0, signaturelen);

    ret = mbedtls_rsa_pkcs1_sign(&rsa, mbedtls_ctr_drbg_random, &ctr_drbg_ctx, MBEDTLS_MD_SHA256, hashlen, hash, signature);
    // printf("mbedtls_rsa_pkcs1_sign: %d\n", ret);
    if (ret != 0)
    {
        goto ret;
    }

    // 3. base64 encode the signature
    ret = atchops_base64_encode(signature, signaturelen, signaturebase64, signaturebase64len, signaturebase64olen);
    // printf("atchops_base64_encode: %d\n", ret);
    if (ret != 0)
    {
        goto ret;
    }

    goto ret;

ret:
{
    free(hash);
    free(signature);
    return ret;
}
}

int atchops_rsa_verify(atchops_rsakey_publickey publickey, atchops_md_type mdtype, const unsigned char *signature, const unsigned long signaturelen, int *result)
{
    return 1; // TODO: implement
}

int atchops_rsa_encrypt(atchops_rsakey_publickey publickey, const unsigned char *plaintext, const unsigned long plaintextlen, unsigned char *ciphertextbase64, const unsigned long ciphertextbase64len, unsigned long *ciphertextbase64olen)
{
    int ret = 1;

    // 1. rsa encrypt the plain text
    mbedtls_rsa_context rsa;
    mbedtls_rsa_init(&rsa);

    ret = mbedtls_rsa_import_raw(&rsa, publickey.n.value, publickey.n.len, NULL, -1, NULL, -1, NULL, -1, publickey.e.value, publickey.e.len);
    // printf("importing rsa: %d\n", ret);
    if (ret != 0)
    {
        goto exit;
    }

    ret = mbedtls_rsa_check_pubkey(&rsa);
    // printf("public key check: %d\n", ret);
    if (ret != 0)
    {
        goto exit;
    }

    ret = mbedtls_rsa_complete(&rsa);
    // printf("mbedtls_rsa_complete: %d\n", ret);
    if (ret != 0)
    {
        goto exit;
    }

    mbedtls_entropy_context entropy_ctx;
    mbedtls_entropy_init(&entropy_ctx);

    mbedtls_ctr_drbg_context ctr_drbg_ctx;
    mbedtls_ctr_drbg_init(&ctr_drbg_ctx);
    ret = mbedtls_ctr_drbg_seed(&ctr_drbg_ctx, mbedtls_entropy_func, &entropy_ctx, NULL, 0);
    // printf("mbedtls_ctr_drbg_seed: %d\n", ret);
    if (ret != 0)
    {
        goto exit;
    }

    const unsigned long outputlen = 256; // 256 bytes is the result of an RSA
    unsigned char *output = malloc(sizeof(unsigned char) * outputlen);
    memset(output, 0, outputlen);

    ret = mbedtls_rsa_pkcs1_encrypt(&rsa, mbedtls_ctr_drbg_random, &ctr_drbg_ctx, plaintextlen, plaintext, output);
    // printf("mbedtls_rsa_pkcs1_encrypt: %d\n", ret);
    if (ret != 0)
    {
        goto exit;
    }

    ret = atchops_base64_encode(output, outputlen, ciphertextbase64, ciphertextbase64len, ciphertextbase64olen);
    // printf("atchops_base64_encode: %d\n", ret);
    if (ret != 0)
    {
        goto exit;
    }

    goto exit;

exit:
{
    free(output);
    return ret;
}
}

int atchops_rsa_decrypt(atchops_rsakey_privatekey privatekey, const unsigned char *ciphertextbase64, const unsigned long ciphertextbase64len, unsigned char *plaintext, const unsigned long plaintextlen, unsigned long *plaintextolen)
{
    int ret = 1;

    // 1. base64 decode the ciphertextbase64
    const unsigned long ciphertextlen = ciphertextbase64len; // the result of the base64 decode of the cipher text should be of sufficient length for the plaintext length they are expecting
    unsigned char *ciphertext = malloc(sizeof(unsigned char) * ciphertextlen);
    memset(ciphertext, 0, ciphertextlen);
    unsigned long ciphertextolen = 0;
    ret = atchops_base64_decode(ciphertextbase64, ciphertextbase64len, ciphertext, ciphertextlen, &ciphertextolen);
    // printf("atchops_base64_decode: %d\n", ret);
    if (ret != 0)
    {
        goto exit;
    }

    // 2. rsa decrypt the base64 decoded ciphertext
    mbedtls_rsa_context rsa;
    mbedtls_rsa_init(&rsa);

    ret = mbedtls_rsa_import_raw(
        &rsa,
        privatekey.n.value,
        privatekey.n.len,
        privatekey.p.value,
        privatekey.p.len,
        privatekey.q.value,
        privatekey.q.len,
        privatekey.d.value,
        privatekey.d.len,
        privatekey.e.value,
        privatekey.e.len);
    // printf("mbedtls_rsa_import_raw: %d\n", ret);
    if (ret != 0)
    {
        goto exit;
    }

    ret = mbedtls_rsa_complete(&rsa);
    // printf("mbedtls_rsa_complete: %d\n", ret);
    if (ret != 0)
    {
        goto exit;
    }

    ret = mbedtls_rsa_check_privkey(&rsa);
    // printf("mbedtls_rsa_check_privkey: %d\n", ret);
    if (ret != 0)
    {
        goto exit;
    }

    mbedtls_entropy_context entropy_ctx;
    mbedtls_entropy_init(&entropy_ctx);

    mbedtls_ctr_drbg_context ctr_drbg_ctx;
    mbedtls_ctr_drbg_init(&ctr_drbg_ctx);
    ret = mbedtls_ctr_drbg_seed(&ctr_drbg_ctx, mbedtls_entropy_func, &entropy_ctx, NULL, 0);
    // printf("mbedtls_ctr_drbg_seed: %d\n", ret);
    if (ret != 0)
    {
        goto exit;
    }

    ret = mbedtls_rsa_pkcs1_decrypt(&rsa, mbedtls_ctr_drbg_random, &ctr_drbg_ctx, plaintextolen, ciphertext, plaintext, plaintextlen);
    // printf("mbedtls_rsa_pkcs1_decrypt: %d\n", ret);
    if (ret != 0)
    {
        goto exit;
    }

    goto exit;

exit:
{
    free(ciphertext);
    return ret;
}
}

int atchops_rsa_generate(atchops_rsakey_publickey *publickey, atchops_rsakey_privatekey *privatekey, const unsigned int keysize)
{
    return 1; // TODO: implement
}
