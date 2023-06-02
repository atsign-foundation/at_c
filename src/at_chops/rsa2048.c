#include <stdlib.h>
#include <string.h>
#include "rsa2048.h"
#include "base64.h"
#include <mbedtls/rsa.h>
#include <mbedtls/asn1.h>

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

void atchops_rsa2048_privatekey_init(RSA2048_PrivateKey **privatekeystruct)
{
    *privatekeystruct = malloc(sizeof(RSA2048_PrivateKey));
    (*privatekeystruct)->n = malloc(sizeof(n_param));
    (*privatekeystruct)->e = malloc(sizeof(e_param));
    (*privatekeystruct)->d = malloc(sizeof(d_param));
    (*privatekeystruct)->p = malloc(sizeof(p_param));
    (*privatekeystruct)->q = malloc(sizeof(q_param));
}

void atchops_rsa2048_privatekey_free(RSA2048_PrivateKey *privatekeystruct)
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

int atchops_populate_publickey(const unsigned char *publickeybase64, const size_t publickeybase64len, RSA2048_PublicKey *publickeystruct)
{
    int ret = 1;

    goto ret;
    ret: {
        return ret;
    }
}
int atchops_populate_privatekey(const unsigned char *privatekeybase64, const size_t privatekeybase64len, RSA2048_PrivateKey *privatekeystruct)
{
    int ret;
    // printf("Public Key: %s\n", publickey);

    size_t dstlen = MAX_TEXT_LENGTH_FORBASE64_ENCODING_OPERATION;
    unsigned char *dst = malloc(sizeof(unsigned char) * dstlen);
    size_t *writtenlen = malloc(sizeof(size_t));
    ret = atchops_base64_decode(dst, dstlen, writtenlen, privatekeybase64, privatekeybase64len);
    if(ret != 0) goto ret;

    // printf("\n");
    // printx(dst, *writtenlen);
    // printf("writtenlen: %lu\n", *writtenlen);
    // printf("\n");

    char *end = dst + (*writtenlen);


    // printf("1st get tag\n");
    size_t *lengthread = malloc(sizeof(size_t));
    ret = mbedtls_asn1_get_tag(&dst, end, lengthread, MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE);
    if(ret != 0) goto ret;
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
    if(ret != 0) goto ret;
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
    if(ret != 0) goto ret;
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
    if(ret != 0) goto ret;
    // printf("ret: %d\n", ret);
    // printf("lengthread4: %lu\n", *lengthread4);
    // printf("*(dst+0) now points to : %02x\n", *(dst+0));
    // printf("*(dst+1) now points to : %02x\n", *(dst+1));
    // printf("*(dst+2) now points to : %02x\n", *(dst+2));
    // printf("*(dst+3) now points to : %02x\n", *(dst+3));

    // printf("5th get tag\n");
    mbedtls_asn1_sequence *seq = malloc(sizeof(mbedtls_asn1_sequence));
    ret = mbedtls_asn1_get_sequence_of(&dst, end, seq, MBEDTLS_ASN1_INTEGER);
    if(ret != 0) goto ret;
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

    ret: {
        return ret;
    }
}