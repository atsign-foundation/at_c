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

static void printx(const unsigned char *buf, const unsigned long len)
{
    for (int i = 0; i < len; i++)
    {
        printf("%02x ", *(buf + i));
    }
    printf("\n");
}

int atchops_rsa_sign(atchops_rsakey_privatekey privatekey, atchops_md_type mdtype, const unsigned char *message, const unsigned long messagelen, unsigned char *signature, const unsigned long signaturelen, unsigned long *signatureolen)
{
    int ret = 1; // error, until successful.

    const unsigned long hashlen = 32;
    unsigned char *hash = malloc(sizeof(char) * hashlen);
    memset(hash, 0, hashlen);
    unsigned long hasholen = 0;
    ret = atchops_sha_hash(mdtype, message, messagelen, hash, hashlen, &hasholen);
    if (ret != 0)
        goto ret;

    // printf("signaturelen: %lu\n", *signaturelen);
    // for(int i = 0; i < *signaturelen; i++)
    // {
    //     printf("%02x ", *(*signature + i));
    // }
    // printf("\n");

    // *signature = malloc(sizeof(unsigned char) * (*signaturelen));

    mbedtls_rsa_context rsa;
    mbedtls_rsa_init(&rsa);

    // printf("\nn: %lu\n", privatekey.n.len);
    // printx(privatekey.n.value, privatekey.n.len);
    // printf("\ne: %lu\n", privatekey.e.len);
    // printx(privatekey.e.value, privatekey.e.len);
    // printf("\nd: %lu\n", privatekey.d.len);
    // printx(privatekey.d.value, privatekey.d.len);
    // printf("\np: %lu\n", privatekey.p.len);
    // printx(privatekey.p.value, privatekey.p.len);
    // printf("\nq: %lu\n", privatekey.q.len);
    // printx(privatekey.q.value, privatekey.q.len);

    ret = mbedtls_rsa_import_raw(&rsa,
                                 privatekey.n.value, privatekey.n.len,
                                 privatekey.p.value, privatekey.p.len,
                                 privatekey.q.value, privatekey.q.len,
                                 privatekey.d.value, privatekey.d.len,
                                 privatekey.e.value, privatekey.e.len);

    // printf("rsa import: %d\n", ret);
    if (ret != 0)
        goto ret;

    ret = mbedtls_rsa_complete(&rsa);
    // printf("rsa complete: %d\n", ret);
    if (ret != 0)
        goto ret;

    ret = mbedtls_rsa_check_privkey(&rsa);
    // printf("rsa check privkey: %d\n", ret);
    if (ret != 0)
        goto ret;

    mbedtls_entropy_context entropy_ctx;
    mbedtls_entropy_init(&entropy_ctx);

    mbedtls_ctr_drbg_context ctr_drbg_ctx;
    mbedtls_ctr_drbg_init(&ctr_drbg_ctx);
    ret = mbedtls_ctr_drbg_seed(&ctr_drbg_ctx, mbedtls_entropy_func, &entropy_ctx, NULL, 0);
    // printf("mbedtls_ctr_drbg_seed: %d\n", ret);
    if (ret != 0)
        goto ret;

    // printf("mbedtls_rsa_self_test: %d\n", mbedtls_rsa_self_test(0));

    // printf("hashlen: %lu\n", hashlen);
    // printf("hash: ");
    // printx(hash, hashlen);
    int buflen = 256; // +1 for null terminator
    unsigned char *buf = malloc(sizeof(unsigned char) * buflen);
    memset(buf, 0, buflen);
    ret = mbedtls_rsa_pkcs1_sign(&rsa, mbedtls_ctr_drbg_random, &ctr_drbg_ctx, MBEDTLS_MD_SHA256, hashlen, hash, buf);
    // printf("mbedtls_rsa_pkcs1_sign: %d\n", ret);
    if (ret != 0)
        goto ret;

    // printf("buflen: %lu\n", buflen);
    // for (int i = 0; i < buflen; i++)
    // {
    //     printf("%02x ", *(buf + i));
    // }
    // printf("\n");

    // base64 encode
    unsigned long dstlen = 4096;
    unsigned char *dst = malloc(sizeof(unsigned char) * dstlen);
    memset(dst, 0, dstlen);
    unsigned long writtenlen = 0;
    ret = atchops_base64_encode(buf, 256, dst, dstlen, &writtenlen);
    // printf("atchops_base64_encode: %d\n", ret);
    if (ret != 0)
        goto ret;

    // append null terminator
    if (writtenlen < dstlen)
    {
        *(dst + writtenlen) = '\0';
    }
    // printf("Challenge: %s\n", dst);

    memset(signature, 0, signaturelen);
    memcpy(signature, dst, writtenlen);
    *signatureolen = writtenlen;

    goto ret;

ret:
{
    free(buf);
    return ret;
}
}

int atchops_rsa_encrypt(atchops_rsakey_publickey publickey, const unsigned char *plaintext, const unsigned long plaintextlen, unsigned char *ciphertext, const unsigned long ciphertextlen, unsigned long *ciphertextolen)
{
    int ret = 1;

    mbedtls_rsa_context rsa;
    mbedtls_rsa_init(&rsa);

    // printf("importing raw...\n");
    ret = mbedtls_rsa_import_raw(&rsa, publickey.n.value, publickey.n.len, NULL, NULL, NULL, NULL, NULL, NULL, publickey.e.value, publickey.e.len);
    if (ret != 0)
        goto ret;

    // printf("n: %d\n", publickey.n_param.len);
    // printx(publickey.n_param.value, publickey.n_param.len);

    // printf("e: %d\n", publickey.e_param.len);
    // printx(publickey.e_param.value, publickey.e_param.len);

    // printf("checking public key...\n");
    ret = mbedtls_rsa_check_pubkey(&rsa);
    // printf("public key check: %d\n", ret);
    if (ret != 0)
        goto ret;

    // printf("completing rsa...\n");
    ret = mbedtls_rsa_complete(&rsa);
    if (ret != 0)
        goto ret;

    // printf("base64 encoding...\n");
    // base64 encode the plain text
    unsigned long dstlen = 2048;
    unsigned char *dst = malloc(sizeof(unsigned char) * dstlen);
    unsigned long olen = 0;
    ret = atchops_base64_encode(plaintext, plaintextlen,  dst, dstlen, &olen);
    // printf("atchops_base64_encode_1: %d\n", ret);
    if (ret != 0)
        goto ret;

    mbedtls_entropy_context entropy_ctx;
    mbedtls_entropy_init(&entropy_ctx);

    // printf("seeding...\n");
    mbedtls_ctr_drbg_context ctr_drbg_ctx;
    mbedtls_ctr_drbg_init(&ctr_drbg_ctx);
    ret = mbedtls_ctr_drbg_seed(&ctr_drbg_ctx, mbedtls_entropy_func, &entropy_ctx, NULL, 0);
    // printf("mbedtls_ctr_drbg_seed: %d\n", ret);
    if (ret != 0)
        goto ret;

    // printf("encrypting...\n");
    // encrypt the base64 encoded text
    unsigned long outputlen = 256; // 256 bytes is the result of an RSA
    unsigned char *output = malloc(sizeof(unsigned char) * outputlen);
    memset(output, 0, outputlen);
    ret = mbedtls_rsa_pkcs1_encrypt(&rsa, mbedtls_ctr_drbg_random, &ctr_drbg_ctx, plaintextlen, plaintext, output);
    if (ret != 0)
        goto ret;

    dstlen = 4096;
    unsigned char *dst2 = malloc(sizeof(unsigned char) * dstlen);
    olen = 0;

    ret = atchops_base64_encode(output, outputlen, dst2, dstlen, &olen);
    if (ret != 0)
        goto ret;

    // printx(dst2, *olen);
    // printf("%s\n", dst2);

    memcpy(ciphertext, dst2, olen);
    *ciphertextolen = olen;

    goto ret;

ret:
{
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
