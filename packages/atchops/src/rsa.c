#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <mbedtls/rsa.h>
#include <mbedtls/asn1.h>
#include <mbedtls/md5.h>
#include <mbedtls/entropy.h>
#include <mbedtls/ctr_drbg.h>
#include "atchops/rsa.h"
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

int atchops_rsa_populate_publickey(atchops_rsa_publickey *publickeystruct, const char *publickeybase64, const unsigned long publickeybase64len)
{
    int ret = 0;

    // 1. base64 decode the key
    unsigned long dstlen = 8192;
    unsigned char *dst = malloc(sizeof(unsigned char) * dstlen);
    unsigned long writtenlen = 0;
    ret = atchops_base64_decode((const unsigned char *) publickeybase64, publickeybase64len, dst, dstlen, &writtenlen);
    if (ret != 0)
        goto ret;

    // printf("\n");
    // printf("writtenlen: %lu\n", *writtenlen);
    // printx(dst, *writtenlen);

    const unsigned char *end = dst + (writtenlen);

    unsigned long *lengthread = malloc(sizeof(unsigned long));
    ret = mbedtls_asn1_get_tag(&dst, end, lengthread, MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE);
    // printf("ret: %d\n", ret);
    if (ret != 0)
        goto ret;
    // printf("lengthread: %lu\n", *lengthread);
    // printf("*(dst+0) now points to : %02x\n", *(dst+0));
    // printf("*(dst+1) now points to : %02x\n", *(dst+1));
    // printf("*(dst+2) now points to : %02x\n", *(dst+2));

    unsigned long *lengthread2 = malloc(sizeof(unsigned long));
    ret = mbedtls_asn1_get_tag(&dst, end, lengthread2, MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE);
    // printf("ret: %d\n", ret);
    if (ret != 0)
        goto ret;
    // printf("lengthread2: %lu\n", *lengthread2);
    // printf("*(dst+0) now points to : %02x\n", *(dst+0));
    // printf("*(dst+1) now points to : %02x\n", *(dst+1));
    // printf("*(dst+2) now points to : %02x\n", *(dst+2));
    dst = dst + (*lengthread2);
    // printf("\n*(dst+0) now points to : %02x\n", *(dst+0));
    // printf("*(dst+1) now points to : %02x\n", *(dst+1));
    // printf("*(dst+2) now points to : %02x\n", *(dst+2));

    unsigned long *lengthread3 = malloc(sizeof(unsigned long));
    ret = mbedtls_asn1_get_tag(&dst, end, lengthread3, MBEDTLS_ASN1_BIT_STRING);
    // printf("ret: %d\n", ret);
    if (ret != 0)
        goto ret;
    // printf("lengthread3: %lu\n", *lengthread3);
    // printf("*(dst+0) now points to : %02x\n", *(dst+0));
    // printf("*(dst+1) now points to : %02x\n", *(dst+1));
    // printf("*(dst+2) now points to : %02x\n", *(dst+2));
    if (*dst == 0x00)
    {
        dst = dst + 1;
    }

    mbedtls_asn1_sequence *seq = malloc(sizeof(mbedtls_asn1_sequence));
    ret = mbedtls_asn1_get_sequence_of(&dst, end, seq, MBEDTLS_ASN1_INTEGER);
    // printf("ret: %d\n", ret);
    if (ret != 0)
        goto ret;

    mbedtls_asn1_sequence *current = seq;
    // while (current != NULL)
    // {
    //     printf("current->buf.tag: %02x\n", current->buf.tag);
    //     printf("current->buf.len: %lu\n", current->buf.len);
    //     printf("current->buf.p:\n");
    //     for(int i = 0; i < current->buf.len; i++)
    //     {
    //         printf("%02x ", *(current->buf.p + i));
    //     }
    //     printf("\n");
    //     current = current->next;
    // }
    publickeystruct->n.len = current->buf.len;
    publickeystruct->n.value = malloc(sizeof(unsigned char) * publickeystruct->n.len);
    memcpy(publickeystruct->n.value, current->buf.p, publickeystruct->n.len);

    current = current->next;
    publickeystruct->e.len = current->buf.len;
    publickeystruct->e.value = malloc(sizeof(unsigned char) * publickeystruct->e.len);
    memcpy(publickeystruct->e.value, current->buf.p, publickeystruct->e.len);

    goto ret;

ret:
{
    return ret;
}
}

int atchops_rsa_populate_privatekey(atchops_rsa_privatekey *privatekeystruct, const char *privatekeybase64, const unsigned long privatekeybase64len)
{
    int ret = 1;

    unsigned long dstlen = 8196;
    unsigned char *dst = malloc(sizeof(unsigned char) * dstlen);
    memset(dst, 0, dstlen);
    unsigned long writtenlen = 0;
    ret = atchops_base64_decode((const unsigned char *) privatekeybase64, privatekeybase64len, dst, dstlen, &writtenlen);
    if (ret != 0)
        goto ret;

    // printf("\n");
    // printx(dst, *writtenlen);
    // printf("writtenlen: %lu\n", *writtenlen);
    // printf("\n");

    unsigned char *end = dst + writtenlen;

    // printf("1st get tag\n");
    unsigned long *lengthread = malloc(sizeof(unsigned long));
    ret = mbedtls_asn1_get_tag(&dst, end, lengthread, MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE);
    if (ret != 0)
        goto ret;
    // printf("ret: %d\n", ret);
    // printf("lengthread: %lu\n", *lengthread);
    // printf("*(dst+0) now points to : %02x\n", *(dst+0));
    // printf("*(dst+1) now points to : %02x\n", *(dst+1));
    // printf("*(dst+2) now points to : %02x\n", *(dst+2));
    // printf("*(dst+3) now points to : %02x\n", *(dst+3));
    // printf("*(dst+4) now points to : %02x\n", *(dst+4));

    // printf("2nd get tag\n");
    unsigned long *lengthread2 = malloc(sizeof(unsigned long));
    ret = mbedtls_asn1_get_tag(&dst, end, lengthread2, MBEDTLS_ASN1_INTEGER);
    if (ret != 0)
        goto ret;
    // printf("ret: %d\n", ret);
    // printf("lengthread2: %lu\n", *lengthread2);
    dst = dst + (*lengthread2);
    // printf("*(dst+0) now points to : %02x\n", *(dst+0));
    // printf("*(dst+1) now points to : %02x\n", *(dst+1));
    // printf("*(dst+2) now points to : %02x\n", *(dst+2));
    // printf("*(dst+3) now points to : %02x\n", *(dst+3));
    // printf("*(dst+4) now points to : %02x\n", *(dst+4));

    // printf("3rd get tag\n");
    unsigned long *lengthread3 = malloc(sizeof(unsigned long));
    ret = mbedtls_asn1_get_tag(&dst, end, lengthread3, MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE);
    if (ret != 0)
        goto ret;
    // printf("ret: %d\n", ret);
    // printf("lengthread3: %lu\n", *lengthread3);
    dst = dst + (*lengthread3);
    // printf("*(dst+0) now points to : %02x\n", *(dst+0));
    // printf("*(dst+1) now points to : %02x\n", *(dst+1));
    // printf("*(dst+2) now points to : %02x\n", *(dst+2));
    // printf("*(dst+3) now points to : %02x\n", *(dst+3));
    // printf("*(dst+4) now points to : %02x\n", *(dst+4));

    // printf("4th get tag\n");
    unsigned long *lengthread4 = malloc(sizeof(unsigned long));
    ret = mbedtls_asn1_get_tag(&dst, end, lengthread4, 0x04);
    if (ret != 0)
        goto ret;
    // printf("ret: %d\n", ret);
    // printf("lengthread4: %lu\n", *lengthread4);
    // printf("*(dst+0) now points to : %02x\n", *(dst+0));
    // printf("*(dst+1) now points to : %02x\n", *(dst+1));
    // printf("*(dst+2) now points to : %02x\n", *(dst+2));
    // printf("*(dst+3) now points to : %02x\n", *(dst+3));

    // printf("5th get tag\n");
    mbedtls_asn1_sequence *seq = malloc(sizeof(mbedtls_asn1_sequence));
    ret = mbedtls_asn1_get_sequence_of(&dst, end, seq, MBEDTLS_ASN1_INTEGER);
    if (ret != 0)
        goto ret;
    // printf("ret: %d\n", ret);

    // traverse seq
    mbedtls_asn1_sequence *current = seq;
    // current = seq;
    // while (current != NULL)
    // {
    //     printf("current->buf.tag: %02x\n", current->buf.tag);
    //     printf("current->buf.len: %lu\n", current->buf.len);
    //     printf("current->buf.p:\n");
    //     for(int i = 0; i < current->buf.len; i++)
    //     {
    //         printf("%02x ", *(current->buf.p + i));
    //     }
    //     printf("\n");

    //     current = current->next;
    // }

    // printf("\n--------");

    current = current->next;

    // printf("n\n");
    privatekeystruct->n.len = current->buf.len;
    privatekeystruct->n.value = malloc(sizeof(unsigned char) * privatekeystruct->n.len);
    memcpy(privatekeystruct->n.value, current->buf.p, privatekeystruct->n.len);

    // printf("e\n");
    current = current->next;
    privatekeystruct->e.len = current->buf.len;
    privatekeystruct->e.value = malloc(sizeof(unsigned char) * privatekeystruct->e.len);
    memcpy(privatekeystruct->e.value, current->buf.p, privatekeystruct->e.len);

    // printf("d\n");
    current = current->next;
    privatekeystruct->d.len = current->buf.len;
    privatekeystruct->d.value = malloc(sizeof(unsigned char) * privatekeystruct->d.len);
    memcpy(privatekeystruct->d.value, current->buf.p, privatekeystruct->d.len);

    // printf("p\n");
    current = current->next;
    privatekeystruct->p.len = current->buf.len;
    privatekeystruct->p.value = malloc(sizeof(unsigned char) * privatekeystruct->p.len);
    memcpy(privatekeystruct->p.value, current->buf.p, privatekeystruct->p.len);

    // printf("q\n");
    current = current->next;
    privatekeystruct->q.len = current->buf.len;
    privatekeystruct->q.value = malloc(sizeof(unsigned char) * privatekeystruct->q.len);
    memcpy(privatekeystruct->q.value, current->buf.p, privatekeystruct->q.len);

    goto ret;

ret:
{
    return ret;
}
}

int atchops_rsa_sign(atchops_rsa_privatekey privatekeystruct, atchops_md_type mdtype, const unsigned char *message, const unsigned long messagelen, unsigned char *signature, const unsigned long signaturelen, unsigned long *signatureolen)
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

    // printf("\nn: %lu\n", privatekeystruct.n.len);
    // printx(privatekeystruct.n.value, privatekeystruct.n.len);
    // printf("\ne: %lu\n", privatekeystruct.e.len);
    // printx(privatekeystruct.e.value, privatekeystruct.e.len);
    // printf("\nd: %lu\n", privatekeystruct.d.len);
    // printx(privatekeystruct.d.value, privatekeystruct.d.len);
    // printf("\np: %lu\n", privatekeystruct.p.len);
    // printx(privatekeystruct.p.value, privatekeystruct.p.len);
    // printf("\nq: %lu\n", privatekeystruct.q.len);
    // printx(privatekeystruct.q.value, privatekeystruct.q.len);

    ret = mbedtls_rsa_import_raw(&rsa,
                                 privatekeystruct.n.value, privatekeystruct.n.len,
                                 privatekeystruct.p.value, privatekeystruct.p.len,
                                 privatekeystruct.q.value, privatekeystruct.q.len,
                                 privatekeystruct.d.value, privatekeystruct.d.len,
                                 privatekeystruct.e.value, privatekeystruct.e.len);

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
    printf("atchops_base64_encode: %d\n", ret);
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
    return ret;
}
}

int atchops_rsa_encrypt(atchops_rsa_publickey publickeystruct, const unsigned char *plaintext, const unsigned long plaintextlen, unsigned char *ciphertext, const unsigned long ciphertextlen, unsigned long *ciphertextolen)
{
    int ret = 1;

    mbedtls_rsa_context rsa;
    mbedtls_rsa_init(&rsa);

    // printf("importing raw...\n");
    ret = mbedtls_rsa_import_raw(&rsa, publickeystruct.n.value, publickeystruct.n.len, NULL, NULL, NULL, NULL, NULL, NULL, publickeystruct.e.value, publickeystruct.e.len);
    if (ret != 0)
        goto ret;

    // printf("n: %d\n", publickeystruct.n_param.len);
    // printx(publickeystruct.n_param.value, publickeystruct.n_param.len);

    // printf("e: %d\n", publickeystruct.e_param.len);
    // printx(publickeystruct.e_param.value, publickeystruct.e_param.len);

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

int atchops_rsa_decrypt(atchops_rsa_privatekey privatekeystruct, const unsigned char *ciphertextbase64, const unsigned long ciphertextbase64len, unsigned char *plaintext, const unsigned long plaintextlen, unsigned long *plaintextolen)
{
    int ret = 1;

    mbedtls_rsa_context rsa;
    mbedtls_rsa_init(&rsa);

    ret = mbedtls_rsa_import_raw(
        &rsa,
        privatekeystruct.n.value,
        privatekeystruct.n.len,
        privatekeystruct.p.value,
        privatekeystruct.p.len,
        privatekeystruct.q.value,
        privatekeystruct.q.len,
        privatekeystruct.d.value,
        privatekeystruct.d.len,
        privatekeystruct.e.value,
        privatekeystruct.e.len);
    if (ret != 0)
        goto ret;

    // printf("n: %lu\n", privatekeystruct.n_param.len);
    // printx(privatekeystruct.n_param.value, privatekeystruct.n_param.len);
    // printf("e: %lu\n", privatekeystruct.e_param.len);
    // printx(privatekeystruct.e_param.value, privatekeystruct.e_param.len);
    // printf("d: %lu\n", privatekeystruct.d_param.len);
    // printx(privatekeystruct.d_param.value, privatekeystruct.d_param.len);
    // printf("p: %lu\n", privatekeystruct.p_param.len);
    // printx(privatekeystruct.p_param.value, privatekeystruct.p_param.len);
    // printf("q: %lu\n", privatekeystruct.q_param.len);
    // printx(privatekeystruct.q_param.value, privatekeystruct.q_param.len);

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
