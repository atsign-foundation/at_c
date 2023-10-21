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
    ret = atchops_base64_encode(signature, signaturelen, signaturebase64, signaturebase64len, &signaturebase64olen);
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

int atchops_rsa_encrypt(atchops_rsakey_publickey publickey, const unsigned char *plaintext, const unsigned long plaintextlen, unsigned char *ciphertextbase64, const unsigned long ciphertextbase64len, unsigned long *ciphertextbase64olen)
{
    int ret = 1;

    // 1. rsa encrypt the plain text
    mbedtls_rsa_context rsa;
    mbedtls_rsa_init(&rsa);

    ret = mbedtls_rsa_import_raw(&rsa, publickey.n.value, publickey.n.len, NULL, NULL, NULL, NULL, NULL, NULL, publickey.e.value, publickey.e.len);
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
    if (ret != 0)
        goto ret;

    // printf("n: %lu\n", privatekey.n_param.len);
    // printx(privatekey.n_param.value, privatekey.n_param.len);
    // printf("e: %lu\n", privatekey.e_param.len);
    // printx(privatekey.e_param.value, privatekey.e_param.len);
    // printf("d: %lu\n", privatekey.d_param.len);
    // printx(privatekey.d_param.value, privatekey.d_param.len);
    // printf("p: %lu\n", privatekey.p_param.len);
    // printx(privatekey.p_param.value, privatekey.p_param.len);
    // printf("q: %lu\n", privatekey.q_param.len);
    // printx(privatekey.q_param.value, privatekey.q_param.len);

    ret = mbedtls_rsa_complete(&rsa);
    if (ret != 0)
        goto ret;

    ret = mbedtls_rsa_check_privkey(&rsa);
    if (ret != 0)
        goto ret;

    // base64 decode the ciphertext
    const unsigned long dstlen = 8192;
    unsigned char *dst = malloc(sizeof(unsigned char) * dstlen);
    memset(dst, 0, dstlen);
    unsigned long writtenlen = 0;
    ret = atchops_base64_decode(ciphertextbase64, ciphertextbase64len, dst, dstlen, &writtenlen);
    // printf("atchops_base64_decode: %d\n", ret);
    if (ret != 0)
        goto ret;

    mbedtls_entropy_context entropy_ctx;
    mbedtls_entropy_init(&entropy_ctx);

    mbedtls_ctr_drbg_context ctr_drbg_ctx;
    mbedtls_ctr_drbg_init(&ctr_drbg_ctx);
    ret = mbedtls_ctr_drbg_seed(&ctr_drbg_ctx, mbedtls_entropy_func, &entropy_ctx, NULL, 0);
    if (ret != 0)
        goto ret;

    // rsa decrypt dst
    const unsigned long outputmaxlen = 4096;
    unsigned char *output = malloc(sizeof(unsigned char) * outputmaxlen);
    memset(output, 0, outputmaxlen);
    unsigned long writtenlen2 = 0;
    ret = mbedtls_rsa_pkcs1_decrypt(&rsa, mbedtls_ctr_drbg_random, &ctr_drbg_ctx, &writtenlen2, dst, output, outputmaxlen);
    // printf("mbedtls_rsa_pkcs1_decrypt: %d\n", ret);
    if (ret != 0)
        goto ret;

    memset(plaintext, 0, plaintextlen);
    memcpy(plaintext, output, writtenlen2);
    *plaintextolen = writtenlen2;

    goto ret;

ret:
{
    return ret;
}
}
