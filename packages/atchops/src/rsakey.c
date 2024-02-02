#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <mbedtls/asn1.h>
#include "atchops/rsa.h"
#include "atchops/rsakey.h"
#include "atchops/base64.h"

#define BASE64_DECODED_KEY_BUFFER_SIZE 8192 // the max buffer size of a decoded RSA key

void atchops_rsakey_publickey_init(atchops_rsakey_publickey *publickey)
{
    memset(publickey, 0, sizeof(atchops_rsakey_publickey));

    publickey->n.len = BASE64_DECODED_KEY_BUFFER_SIZE;
    publickey->n.value = (unsigned char *)malloc(sizeof(unsigned char) * publickey->n.len);

    publickey->e.len = BASE64_DECODED_KEY_BUFFER_SIZE;
    publickey->e.value = (unsigned char *)malloc(sizeof(unsigned char) * publickey->e.len);
}
void atchops_rsakey_publickey_free(atchops_rsakey_publickey *publickey)
{
    free(publickey->n.value);
    free(publickey->e.value);
}

void atchops_rsakey_privatekey_init(atchops_rsakey_privatekey *privatekey)
{
    memset(privatekey, 0, sizeof(atchops_rsakey_privatekey));

    privatekey->n.len = BASE64_DECODED_KEY_BUFFER_SIZE;
    privatekey->n.value = malloc(sizeof(unsigned char) * privatekey->n.len);

    privatekey->e.len = BASE64_DECODED_KEY_BUFFER_SIZE;
    privatekey->e.value = malloc(sizeof(unsigned char) * privatekey->e.len);

    privatekey->d.len = BASE64_DECODED_KEY_BUFFER_SIZE;
    privatekey->d.value = malloc(sizeof(unsigned char) * privatekey->d.len);

    privatekey->p.len = BASE64_DECODED_KEY_BUFFER_SIZE;
    privatekey->p.value = malloc(sizeof(unsigned char) * privatekey->p.len);

    privatekey->q.len = BASE64_DECODED_KEY_BUFFER_SIZE;
    privatekey->q.value = malloc(sizeof(unsigned char) * privatekey->q.len);
}

void atchops_rsakey_privatekey_free(atchops_rsakey_privatekey *privatekey)
{
    free(privatekey->n.value);
    free(privatekey->e.value);
    free(privatekey->d.value);
    free(privatekey->p.value);
    free(privatekey->q.value);
}

int atchops_rsakey_populate_publickey(atchops_rsakey_publickey *publickey, const char *publickeybase64, const unsigned long publickeybase64len)
{
    int ret = 0;

    // 1. base64 decode the key
    unsigned long dstlen = BASE64_DECODED_KEY_BUFFER_SIZE;
    unsigned char *dst = (unsigned char *)malloc(sizeof(unsigned char) * dstlen);
    memset(dst, 0, dstlen);
    unsigned long writtenlen = 0;
    ret = atchops_base64_decode((const unsigned char *)publickeybase64, publickeybase64len, dst, dstlen, &writtenlen);
    if (ret != 0)
    {
        goto exit;
    }

    unsigned char *end = dst + writtenlen;

    unsigned long lengthread = 0;
    ret = mbedtls_asn1_get_tag(&dst, end, &lengthread, MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE);
    if (ret != 0)
    {
        goto exit;
    }

    unsigned long lengthread2 = 0;
    ret = mbedtls_asn1_get_tag(&dst, end, &lengthread2, MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE);
    if (ret != 0)
    {
        goto exit;
    }
    dst = dst + (lengthread2);

    unsigned long lengthread3 = 0;
    ret = mbedtls_asn1_get_tag(&dst, end, &lengthread3, MBEDTLS_ASN1_BIT_STRING);
    if (ret != 0)
    {
        goto exit;
    }

    if (*dst == 0x00)
    {
        dst = dst + 1;
    }

    unsigned char *p = dst;

    mbedtls_asn1_sequence seq;
    memset(&seq, 0, sizeof(mbedtls_asn1_sequence));
    ret = mbedtls_asn1_get_sequence_of(&p, end, &seq, MBEDTLS_ASN1_INTEGER);
    if (ret != 0)
    {
        goto exit;
    }

    mbedtls_asn1_sequence *current = &seq;
    publickey->n.len = current->buf.len;
    memcpy(publickey->n.value, current->buf.p, publickey->n.len);

    current = current->next;
    publickey->e.len = current->buf.len;
    memcpy(publickey->e.value, current->buf.p, publickey->e.len);

    goto exit;

exit:
{
    // dst is already freed by mbedtls_asn1_get_sequence_of
    // mbedtls_asn1_sequence does not need to be freed.
    return ret;
}
}

int atchops_rsakey_populate_privatekey(atchops_rsakey_privatekey *privatekey, const char *privatekeybase64, const unsigned long privatekeybase64len)
{
    int ret = 1;

    unsigned long dstlen = BASE64_DECODED_KEY_BUFFER_SIZE;
    unsigned char *dst = malloc(sizeof(unsigned char) * dstlen);
    memset(dst, 0, dstlen);
    unsigned long writtenlen = 0;
    ret = atchops_base64_decode((const unsigned char *)privatekeybase64, privatekeybase64len, dst, dstlen, &writtenlen);
    if (ret != 0)
    {
        goto exit;
    }

    unsigned char *end = dst + writtenlen;

    unsigned long lengthread = 0;
    ret = mbedtls_asn1_get_tag(&dst, end, &lengthread, MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE);
    if (ret != 0)
    {
        goto exit;
    }

    unsigned long lengthread2 = 0;
    ret = mbedtls_asn1_get_tag(&dst, end, &lengthread2, MBEDTLS_ASN1_INTEGER);
    if (ret != 0)
    {
        goto exit;
    }
    dst = dst + lengthread2;

    unsigned long lengthread3 = 0;
    ret = mbedtls_asn1_get_tag(&dst, end, &lengthread3, MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE);
    if (ret != 0)
    {
        goto exit;
    }
    dst = dst + lengthread3;

    unsigned long lengthread4 = 0;
    ret = mbedtls_asn1_get_tag(&dst, end, &lengthread4, 0x04);
    if (ret != 0)
    {
        goto exit;
    }

    unsigned char *p = dst;

    mbedtls_asn1_sequence seq;
    memset(&seq, 0, sizeof(mbedtls_asn1_sequence));

    ret = mbedtls_asn1_get_sequence_of(&p, end, &seq, MBEDTLS_ASN1_INTEGER);
    if (ret != 0)
    {
        goto exit;
    }

    mbedtls_asn1_sequence *current = &seq;
    current = current->next;

    privatekey->n.len = current->buf.len;
    memcpy(privatekey->n.value, current->buf.p, privatekey->n.len);

    current = current->next;
    privatekey->e.len = current->buf.len;
    memcpy(privatekey->e.value, current->buf.p, privatekey->e.len);

    current = current->next;
    privatekey->d.len = current->buf.len;
    memcpy(privatekey->d.value, current->buf.p, privatekey->d.len);

    current = current->next;
    privatekey->p.len = current->buf.len;
    memcpy(privatekey->p.value, current->buf.p, privatekey->p.len);

    current = current->next;
    privatekey->q.len = current->buf.len;
    memcpy(privatekey->q.value, current->buf.p, privatekey->q.len);

    goto exit;

exit:
{
    // dst is already freed by mbedtls_asn1_get_sequence_of
    // mbedtls_asn1_sequence does not need to be freed.
    return ret;
}
}