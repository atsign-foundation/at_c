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

int atchops_populate_publickey(const unsigned char *publickeybase64, const size_t publickeybase64len, RSA2048_PublicKey *publickeystruct)
{
    return 1;
}
int atchops_populate_privatekey(const unsigned char *privatekeybase64, const size_t privatekeybase64len, RSA2048_PrivateKey *privatekeystruct)
{
    // printf("Public Key: %s\n", publickey);

    size_t dstlen = MAX_TEXT_LENGTH_FORBASE64_ENCODING_OPERATION;
    unsigned char *dst = malloc(sizeof(unsigned char) * dstlen);
    size_t *writtenlen = malloc(sizeof(size_t));
    atchops_base64_decode(dst, dstlen, writtenlen, privatekeybase64, privatekeybase64len);

    // printf("\n");
    // printx(dst, *writtenlen);
    // printf("writtenlen: %lu\n", *writtenlen);
    // printf("\n");

    char *end = dst + (*writtenlen);

    int ret;

    // printf("1st get tag\n");
    size_t *lengthread = malloc(sizeof(size_t));
    ret = mbedtls_asn1_get_tag(&dst, end, lengthread, MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE);
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
    // printf("ret: %d\n", ret);
    // printf("lengthread4: %lu\n", *lengthread4);
    // printf("*(dst+0) now points to : %02x\n", *(dst+0));
    // printf("*(dst+1) now points to : %02x\n", *(dst+1));
    // printf("*(dst+2) now points to : %02x\n", *(dst+2));
    // printf("*(dst+3) now points to : %02x\n", *(dst+3));

    // printf("5th get tag\n");
    mbedtls_asn1_sequence *seq = malloc(sizeof(mbedtls_asn1_sequence));
    ret = mbedtls_asn1_get_sequence_of(&dst, end, seq, MBEDTLS_ASN1_INTEGER);
    // printf("ret: %d\n", ret);

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

    //     unsigned char *hex_string = malloc(sizeof(unsigned char) * (current->buf.len));
    //     strncpy(hex_string, current->buf.p, current->buf.len);

    //     current = current->next;
    // }

    unsigned char *hex_string_n = malloc(sizeof(unsigned char) * (current->buf.len));
    strncpy(hex_string_n, current->buf.p, current->buf.len);

    printx(hex_string_n, current->buf.len);

    current = current->next;
    unsigned char *hex_string_e = malloc(sizeof(unsigned char) * (current->buf.len));
    strncpy(hex_string_e, current->buf.p, current->buf.len);

    printx(hex_string_e, current->buf.len);

    current = current->next;

    unsigned char *hex_string_d = malloc(sizeof(unsigned char) * (current->buf.len));
    strncpy(hex_string_d, current->buf.p, current->buf.len);

    printx(hex_string_d, current->buf.len);

    current = current->next;

    unsigned char *hex_string_p = malloc(sizeof(unsigned char) * (current->buf.len));
    strncpy(hex_string_p, current->buf.p, current->buf.len);

    printx(hex_string_p, current->buf.len);

    current = current->next;

    unsigned char *hex_string_q = malloc(sizeof(unsigned char) * (current->buf.len));
    strncpy(hex_string_q, current->buf.p, current->buf.len);

    printx(hex_string_q, current->buf.len);

    return 0;
}