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

int atchops_rsa_populate_publickey(const char *publickeybase64, const size_t publickeybase64len, atchops_rsa_publickey *publickeystruct)
{
    int ret = 0;

    // 1. base64 decode the key
    size_t dstlen = MAX_TEXT_LENGTH_FORBASE64_ENCODING_OPERATION;
    unsigned char *dst = malloc(sizeof(unsigned char) * dstlen);
    size_t *writtenlen = malloc(sizeof(size_t));
    ret = atchops_base64_decode(dst, dstlen, writtenlen, publickeybase64, publickeybase64len);
    if (ret != 0)
        goto ret;

    // printf("\n");
    // printf("writtenlen: %lu\n", *writtenlen);
    // printx(dst, *writtenlen);

    const unsigned char *end = dst + (*writtenlen);

    size_t *lengthread = malloc(sizeof(size_t));
    ret = mbedtls_asn1_get_tag(&dst, end, lengthread, MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE);
    // printf("ret: %d\n", ret);
    if (ret != 0)
        goto ret;
    // printf("lengthread: %lu\n", *lengthread);
    // printf("*(dst+0) now points to : %02x\n", *(dst+0));
    // printf("*(dst+1) now points to : %02x\n", *(dst+1));
    // printf("*(dst+2) now points to : %02x\n", *(dst+2));

    size_t *lengthread2 = malloc(sizeof(size_t));
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

    size_t *lengthread3 = malloc(sizeof(size_t));
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
    publickeystruct->n_param.len = current->buf.len;
    publickeystruct->n_param.value = malloc(sizeof(unsigned char) * publickeystruct->n_param.len);
    memcpy(publickeystruct->n_param.value, current->buf.p, publickeystruct->n_param.len);

    current = current->next;
    publickeystruct->e_param.len = current->buf.len;
    publickeystruct->e_param.value = malloc(sizeof(unsigned char) * publickeystruct->e_param.len);
    memcpy(publickeystruct->e_param.value, current->buf.p, publickeystruct->e_param.len);

    goto ret;

    ret:
    {
        return ret;
    }
}

int atchops_rsa_populate_privatekey(const char *privatekeybase64, const size_t privatekeybase64len, atchops_rsa_privatekey *privatekeystruct)
{
    int ret = 1;

    size_t dstlen = MAX_TEXT_LENGTH_FORBASE64_ENCODING_OPERATION;
    unsigned char *dst = malloc(sizeof(unsigned char) * dstlen);
    size_t *writtenlen = malloc(sizeof(size_t));
    ret = atchops_base64_decode(dst, dstlen, writtenlen, privatekeybase64, privatekeybase64len);
    if (ret != 0)
        goto ret;

    // printf("\n");
    // printx(dst, *writtenlen);
    // printf("writtenlen: %lu\n", *writtenlen);
    // printf("\n");

    char *end = dst + (*writtenlen);

    // printf("1st get tag\n");
    size_t *lengthread = malloc(sizeof(size_t));
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
    size_t *lengthread2 = malloc(sizeof(size_t));
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
    size_t *lengthread3 = malloc(sizeof(size_t));
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
    size_t *lengthread4 = malloc(sizeof(size_t));
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
    privatekeystruct->n_param.len = current->buf.len;
    privatekeystruct->n_param.value = malloc(sizeof(unsigned char) * privatekeystruct->n_param.len);
    memcpy(privatekeystruct->n_param.value, current->buf.p, privatekeystruct->n_param.len);

    // printf("e\n");
    current = current->next;
    privatekeystruct->e_param.len = current->buf.len;
    privatekeystruct->e_param.value = malloc(sizeof(unsigned char) * privatekeystruct->e_param.len);
    memcpy(privatekeystruct->e_param.value, current->buf.p, privatekeystruct->e_param.len);

    // printf("d\n");
    current = current->next;
    privatekeystruct->d_param.len = current->buf.len;
    privatekeystruct->d_param.value = malloc(sizeof(unsigned char) * privatekeystruct->d_param.len);
    memcpy(privatekeystruct->d_param.value, current->buf.p, privatekeystruct->d_param.len);

    // printf("p\n");
    current = current->next;
    privatekeystruct->p_param.len = current->buf.len;
    privatekeystruct->p_param.value = malloc(sizeof(unsigned char) * privatekeystruct->p_param.len);
    memcpy(privatekeystruct->p_param.value, current->buf.p, privatekeystruct->p_param.len);

    // printf("q\n");
    current = current->next;
    privatekeystruct->q_param.len = current->buf.len;
    privatekeystruct->q_param.value = malloc(sizeof(unsigned char) * privatekeystruct->q_param.len);
    memcpy(privatekeystruct->q_param.value, current->buf.p, privatekeystruct->q_param.len);

    goto ret;

    ret:
    {
        return ret;
    }
}

int atchops_rsa_sign(atchops_rsa_privatekey privatekeystruct, atchops_md_type mdtype, unsigned char **signature, size_t *signaturelen, const unsigned char *message, const size_t messagelen)
{
    int ret = 1; // error, until successful.

    const size_t hashlen = 32;
    unsigned char *hash = malloc(sizeof(char) * hashlen);
    size_t hasholen = 0;
    ret = atchops_sha_hash(hash, hashlen, &hasholen, message, messagelen, mdtype);
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

    // printf("\nn: %lu\n", privatekeystruct->n->len);
    // printx(privatekeystruct->n->n, privatekeystruct->n->len);
    // printf("\ne: %lu\n", privatekeystruct->e->len);
    // printx(privatekeystruct->e->e, privatekeystruct->e->len);
    // printf("\nd: %lu\n", privatekeystruct->d->len);
    // printx(privatekeystruct->d->d, privatekeystruct->d->len);
    // printf("\np: %lu\n", privatekeystruct->p->len);
    // printx(privatekeystruct->p->p, privatekeystruct->p->len);
    // printf("\nq: %lu\n", privatekeystruct->q->len);
    // printx(privatekeystruct->q->q, privatekeystruct->q->len);

    ret = mbedtls_rsa_import_raw(&rsa,
        privatekeystruct.n_param.value, privatekeystruct.n_param.len,
        privatekeystruct.p_param.value, privatekeystruct.p_param.len,
        privatekeystruct.q_param.value, privatekeystruct.q_param.len,
        privatekeystruct.d_param.value, privatekeystruct.d_param.len,
        privatekeystruct.e_param.value, privatekeystruct.e_param.len);

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
    int buflen = 256;
    unsigned char *buf = malloc(sizeof(unsigned char) * buflen + 1); // +1 for null terminator
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
    size_t *writtenlen = malloc(sizeof(size_t));
    unsigned char *dst = malloc(sizeof(unsigned char) * MAX_TEXT_LENGTH_FORBASE64_ENCODING_OPERATION);
    ret = atchops_base64_encode(dst, MAX_TEXT_LENGTH_FORBASE64_ENCODING_OPERATION, writtenlen, buf, buflen);
    if (ret != 0)
        goto ret;

    // append null terminator
    *(dst + *writtenlen) = '\0';
    // printf("Challenge: %s\n", dst);

    *signature = dst;
    *signaturelen = *writtenlen;

    goto ret;

    ret:
    {
        return ret;
    }
}

int atchops_rsa_encrypt(atchops_rsa_publickey publickeystruct, const char *plaintext, const size_t plaintextlen, char **ciphertext, size_t *ciphertextolen)
{
    int ret = 1;

    mbedtls_rsa_context rsa;
    mbedtls_rsa_init(&rsa);

    // printf("importing raw...\n");
    ret = mbedtls_rsa_import_raw(&rsa, publickeystruct.n_param.value, publickeystruct.n_param.len, NULL, NULL, NULL, NULL, NULL, NULL, publickeystruct.e_param.value, publickeystruct.e_param.len);
    if(ret != 0)
        goto ret;

    // printf("n: %d\n", publickeystruct.n_param.len);
    // printx(publickeystruct.n_param.value, publickeystruct.n_param.len);

    // printf("e: %d\n", publickeystruct.e_param.len);
    // printx(publickeystruct.e_param.value, publickeystruct.e_param.len);


    // printf("checking public key...\n");
    ret = mbedtls_rsa_check_pubkey(&rsa);
    // printf("public key check: %d\n", ret);
    if(ret != 0)
        goto ret;

    // printf("completing rsa...\n");
    ret = mbedtls_rsa_complete(&rsa);
    if(ret != 0)
        goto ret;

    // printf("base64 encoding...\n");
    // base64 encode the plain text
    size_t dstlen = MAX_TEXT_LENGTH_FORBASE64_ENCODING_OPERATION;
    unsigned char *dst = malloc(sizeof(unsigned char) * dstlen);
    size_t *olen = malloc(sizeof(size_t));
    ret = atchops_base64_encode(dst, dstlen, olen, plaintext, plaintextlen);
    if(ret != 0)
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
    size_t outputlen = 256; // 256 bytes is the result of an RSA
    unsigned char *output = malloc(sizeof(unsigned char) * outputlen);
    ret = mbedtls_rsa_pkcs1_encrypt(&rsa, mbedtls_ctr_drbg_random, &ctr_drbg_ctx, plaintextlen, plaintext, output);
    if(ret != 0)
        goto ret;

    dstlen = MAX_TEXT_LENGTH_FORBASE64_ENCODING_OPERATION;
    unsigned char *dst2 = malloc(sizeof(unsigned char) * dstlen);
    free(olen);
    *olen = malloc(sizeof(size_t));

    ret = atchops_base64_encode(dst2, dstlen, olen, output, outputlen);
    if(ret != 0)
        goto ret;

    // printx(dst2, *olen);
    // printf("%s\n", dst2);

    *ciphertext = dst2;
    *ciphertextolen = *olen;

    goto ret;

    ret:
    {
        return ret;
    }

}

int atchops_rsa_decrypt(atchops_rsa_privatekey privatekeystruct, const char *ciphertextbase64encoded, const size_t ciphertextbase64encodedlen, char **plaintext, size_t *plaintextolen)
{
    int ret = 1;

    mbedtls_rsa_context rsa;
    mbedtls_rsa_init(&rsa);

    ret = mbedtls_rsa_import_raw(&rsa, privatekeystruct.n_param.value, privatekeystruct.n_param.len, privatekeystruct.p_param.value, privatekeystruct.p_param.len, privatekeystruct.q_param.value, privatekeystruct.q_param.len, privatekeystruct.d_param.value, privatekeystruct.d_param.len, privatekeystruct.e_param.value, privatekeystruct.e_param.len);
    if(ret != 0)
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
    if(ret != 0)
        goto ret;

    ret = mbedtls_rsa_check_privkey(&rsa);
    if(ret != 0)
        goto ret;


    // base64 decode the ciphertext
    const size_t dstlen = MAX_TEXT_LENGTH_FORBASE64_ENCODING_OPERATION;
    unsigned char *dst = malloc(sizeof(unsigned char) * dstlen);
    size_t *writtenlen = malloc(sizeof(size_t));
    ret = atchops_base64_decode(dst, dstlen, writtenlen, ciphertextbase64encoded, ciphertextbase64encodedlen);
    if(ret != 0)
        goto ret;

    mbedtls_entropy_context entropy_ctx;
    mbedtls_entropy_init(&entropy_ctx);

    mbedtls_ctr_drbg_context ctr_drbg_ctx;
    mbedtls_ctr_drbg_init(&ctr_drbg_ctx);
    ret = mbedtls_ctr_drbg_seed(&ctr_drbg_ctx, mbedtls_entropy_func, &entropy_ctx, NULL, 0);
    if (ret != 0)
        goto ret;

    // rsa decrypt dst
    const size_t outputmaxlen = 5000;
    unsigned char *output = malloc(sizeof(unsigned char) * outputmaxlen);
    size_t *writtenlen2 = malloc(sizeof(size_t));
    ret = mbedtls_rsa_pkcs1_decrypt(&rsa, mbedtls_ctr_drbg_random, &ctr_drbg_ctx, writtenlen2, dst, output, outputmaxlen);
    if(ret != 0)
        goto ret;

    // base64 decode the output
    // const size_t dstlen2 = MAX_TEXT_LENGTH_FORBASE64_ENCODING_OPERATION;
    // unsigned char *dst2 = malloc(sizeof(unsigned char) * dstlen2);
    // size_t *writtenlen3 = malloc(sizeof(size_t));
    // printf("7\n");
    // ret = atchops_base64_encode(dst2, dstlen2, writtenlen3, output, *writtenlen);
    // if(ret != 0)
    //     goto ret;

    *plaintext = output;
    *plaintextolen = *writtenlen2;

    goto ret;

    ret: {
        return ret;
    }
}
