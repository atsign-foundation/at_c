#ifdef BUILD_MBEDTLS
#ifdef __cplusplus
extern "C"
{
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "rsa2048.h"
#include "base64.h"
#include <mbedtls/rsa.h>
#include <mbedtls/asn1.h>
#include <mbedtls/md5.h>
#include <mbedtls/entropy.h>
#include <mbedtls/ctr_drbg.h>

    void printx(unsigned char *data, size_t len)
    {
        for (size_t i = 0; i < len; i++)
        {
            printf("%02x ", data[i]);
        }
        printf("\n");
    }

    void copy(unsigned char *dst, unsigned char *src, size_t len)
    {
        for (size_t i = 0; i < len; i++)
        {
            dst[i] = src[i];
        }
    }
    void atchops_rsa2048_publickey_init(atchops_rsa2048_publickey **publickeystruct)
    {
        *publickeystruct = malloc(sizeof(atchops_rsa2048_publickey));
        (*publickeystruct)->n = malloc(sizeof(n_param));
        (*publickeystruct)->e = malloc(sizeof(e_param));
    }

    void atchops_rsa2048_privatekey_init(atchops_rsa2048_privatekey **privatekeystruct)
    {
        *privatekeystruct = malloc(sizeof(atchops_rsa2048_privatekey));
        (*privatekeystruct)->n = malloc(sizeof(n_param));
        (*privatekeystruct)->e = malloc(sizeof(e_param));
        (*privatekeystruct)->d = malloc(sizeof(d_param));
        (*privatekeystruct)->p = malloc(sizeof(p_param));
        (*privatekeystruct)->q = malloc(sizeof(q_param));
    }
    void atchops_rsa2048_publickey_free(atchops_rsa2048_publickey *publickeystruct)
    {
        free(publickeystruct->n->n);
        free(publickeystruct->n);
        free(publickeystruct->e->e);
        free(publickeystruct->e);
        free(publickeystruct);
    }

    void atchops_rsa2048_privatekey_free(atchops_rsa2048_privatekey *privatekeystruct)
    {
        free(privatekeystruct->n->n);
        free(privatekeystruct->n);
        free(privatekeystruct->e->e);
        free(privatekeystruct->e);
        free(privatekeystruct->d->d);
        free(privatekeystruct->d);
        free(privatekeystruct->p->p);
        free(privatekeystruct->p);
        free(privatekeystruct->q->q);
        free(privatekeystruct->q);
        free(privatekeystruct);
    }

    int atchops_rsa2048_populate_publickey(const unsigned char *publickeybase64, const size_t publickeybase64len, atchops_rsa2048_publickey *publickeystruct)
    {
        int ret = 1;

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

        // traverse seq
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

        publickeystruct->e->e = malloc(sizeof(unsigned char) * current->buf.len);
        publickeystruct->e->len = current->buf.len;
        copy(publickeystruct->e->e, current->buf.p, current->buf.len);

        current = current->next;
        publickeystruct->n->n = malloc(sizeof(unsigned char) * current->buf.len);
        publickeystruct->n->len = current->buf.len;
        copy(publickeystruct->n->n, current->buf.p, current->buf.len);

        goto ret;

    ret:
    {
        return ret;
    }
    }
    int atchops_rsa2048_populate_privatekey(const unsigned char *privatekeybase64, const size_t privatekeybase64len, atchops_rsa2048_privatekey *privatekeystruct)
    {
        int ret;
        // printf("Public Key: %s\n", publickey);

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
        privatekeystruct->n->n = malloc(sizeof(unsigned char) * current->buf.len);
        privatekeystruct->n->len = current->buf.len;
        copy(privatekeystruct->n->n, current->buf.p, current->buf.len);

        // printf("e\n");
        current = current->next;
        privatekeystruct->e->e = malloc(sizeof(unsigned char) * current->buf.len);
        privatekeystruct->e->len = current->buf.len;
        copy(privatekeystruct->e->e, current->buf.p, current->buf.len);

        // printf("d\n");
        current = current->next;
        privatekeystruct->d->d = malloc(sizeof(unsigned char) * current->buf.len);
        privatekeystruct->d->len = current->buf.len;
        copy(privatekeystruct->d->d, current->buf.p, current->buf.len);

        // printf("p\n");
        current = current->next;
        privatekeystruct->p->p = malloc(sizeof(unsigned char) * current->buf.len);
        privatekeystruct->p->len = current->buf.len;
        copy(privatekeystruct->p->p, current->buf.p, current->buf.len);

        // printf("q\n");
        current = current->next;
        privatekeystruct->q->q = malloc(sizeof(unsigned char) * current->buf.len);
        privatekeystruct->q->len = current->buf.len;
        copy(privatekeystruct->q->q, current->buf.p, current->buf.len);

        goto ret;

    ret:
    {
        return ret;
    }
    }

    int atchops_rsa2048_sign(atchops_rsa2048_privatekey *privatekeystruct, atchops_md_type mdtype, unsigned char **signature, size_t *signaturelen, const unsigned char *message, const size_t messagelen)
    {
        int ret = 1;

        mbedtls_md_context_t md_ctx;
        mbedtls_md_init(&md_ctx);

        mbedtls_md_type_t md_type = mdtype; // TODO dynamic

        ret = mbedtls_md_setup(&md_ctx, mbedtls_md_info_from_type(md_type), 0);
        if (ret != 0) goto ret;


        ret = mbedtls_md_starts(&md_ctx);
        if (ret != 0) goto ret;

        ret = mbedtls_md_update(&md_ctx, message, messagelen);
        if (ret != 0) goto ret;

        const size_t hashlen = mbedtls_md_get_size(mbedtls_md_info_from_type(md_type));
        printf("hashlen: %lu\n", hashlen);
        unsigned char *hash = malloc(sizeof(unsigned char) * hashlen);

        ret = mbedtls_md_finish(&md_ctx, hash);
        if (ret != 0) goto ret;

        mbedtls_md_free(&md_ctx);

        // printf("signaturelen: %lu\n", *signaturelen);
        // for(int i = 0; i < *signaturelen; i++)
        // {
        //     printf("%02x ", *(*signature + i));
        // }
        // printf("\n");

        *signaturelen = 2506;
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
                                     privatekeystruct->n->n, privatekeystruct->n->len,
                                     privatekeystruct->p->p, privatekeystruct->p->len,
                                     privatekeystruct->q->q, privatekeystruct->q->len,
                                     privatekeystruct->d->d, privatekeystruct->d->len,
                                     privatekeystruct->e->e, privatekeystruct->e->len);
        printf("rsa import: %d\n", ret);
        if (ret != 0) goto ret;

        ret = mbedtls_rsa_complete(&rsa);
        printf("rsa complete: %d\n", ret);
        if (ret != 0) goto ret;

        ret = mbedtls_rsa_check_privkey(&rsa);
        printf("rsa check privkey: %d\n", ret);
        if (ret != 0) goto ret;

        mbedtls_entropy_context entropy_ctx;
        mbedtls_entropy_init(&entropy_ctx);

        mbedtls_ctr_drbg_context ctr_drbg_ctx;
        mbedtls_ctr_drbg_init(&ctr_drbg_ctx);
        ret = mbedtls_ctr_drbg_seed(&ctr_drbg_ctx, mbedtls_entropy_func, &entropy_ctx, "rsa_sign", strlen("rsa_sign"));
        printf("mbedtls_ctr_drbg_seed: %d\n", ret);
        if (ret != 0)
            goto ret;

        printf("mbedtls_rsa_self_test: %d\n", mbedtls_rsa_self_test(0));

        printf("hashlen: %lu\n", hashlen);
        printf("hash: ");
        printx(hash, hashlen);
        int buflen = 256;
        unsigned char *buf = malloc(sizeof(unsigned char) * buflen + 1); // +1 for null terminator
        ret = mbedtls_rsa_pkcs1_sign(&rsa, mbedtls_ctr_drbg_random, &ctr_drbg_ctx, MBEDTLS_MD_SHA256, hashlen, hash, buf);
        printf("mbedtls_rsa_pkcs1_sign: %d\n", ret);
        if (ret != 0) goto ret;

        printf("buflen: %lu\n", buflen);
        for (int i = 0; i < buflen; i++)
        {
            printf("%02x ", *(buf + i));
        }
        printf("\n");

        // base64 encode
        size_t *writtenlen = malloc(sizeof(size_t));
        unsigned char *dst = malloc(sizeof(unsigned char) * MAX_TEXT_LENGTH_FORBASE64_ENCODING_OPERATION);
        ret = atchops_base64_encode(dst, MAX_TEXT_LENGTH_FORBASE64_ENCODING_OPERATION, writtenlen, buf, buflen);
        if (ret != 0) goto ret;

        // append null terminator
        *(dst + *writtenlen) = '\0';
        printf("Challenge: %s\n", dst);

        *signature = dst;
        *signaturelen = *writtenlen;

        goto ret;

    ret:
    {
        return ret;
    }
    }

    // todo
    // verify

    int atchops_rsa2048_encrypt(atchops_rsa2048_publickey *publickeystruct, const unsigned char *plaintext, const size_t plaintextlen, unsigned char *ciphertext, const size_t ciphertextlen, size_t *ciphertextolen)
    {
        int ret = 1;

        printf("starting encrypt..\n");

        mbedtls_mpi *n = malloc(sizeof(mbedtls_mpi));
        mbedtls_mpi *e = malloc(sizeof(mbedtls_mpi));

        mbedtls_mpi_init(n);
        mbedtls_mpi_init(e);

        ret = mbedtls_mpi_read_binary(n, publickeystruct->n->n, publickeystruct->n->len);
        if (ret != 0)
            goto ret;

        ret = mbedtls_mpi_read_binary(e, publickeystruct->e->e, publickeystruct->e->len);
        if (ret != 0)
            goto ret;

        mbedtls_rsa_context rsa;
        mbedtls_rsa_init(&rsa);

        ret = mbedtls_rsa_import(&rsa, n, NULL, NULL, NULL, e);
        if (ret != 0)
            goto ret;

        goto ret;

    ret:
    {
        return ret;
    }
    }

    int atchops_rsa2048_decrypt(atchops_rsa2048_privatekey *privatekeystruct, const unsigned char *ciphertext, const size_t ciphertextlen, unsigned char *plaintext, const size_t *plaintextlen, size_t *plaintextolen)
    {
        int ret = 1;

        goto ret;

    ret:
    {
        return ret;
    }
    }

#ifdef __cplusplus
}
#endif
#endif