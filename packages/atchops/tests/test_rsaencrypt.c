
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "atchops/rsa.h"

#define PUBLICKEYBASE64 "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAg3P7mefqZg2GNQPiEHYinmTYUcbbW2Ar9Wi5LCD/uRZNRiQJypbAQbpvk6fAo1wh5Ntp1kjPGHrIikUBVREItTkulobOOPVNaC5FUg86kQJ2Wk+ZyPaCIfrto7Gv+yn2DiKqjdYdexjmaKbMO90WSZ7yEmC2mq8bRQASD0PoG3RX1skhGkV1FvPbH4OEDuzMxHfGcCvCi3+BPcbgjLIT/dKe2zAHS5/fE9OK1bz+/FutJTF8M6LKQY8E+h2cQjTEn3RRJlcMp4rwq/0GNmm3mNY5EhUcamKiSWILG9a8nYzeIUafXmESCZk+J1yVu9QcmXP8Dokv+4KLv76/Y1RsqQIDAQAB"

#define PLAINTEXT "banana"

static void printx(const char *str, size_t len)
{
    printf("hex: ");
    for(size_t i = 0; i < len; i++)
    {
        printf("%02x", str[i]);
    }
    printf("\n");
}

int main()
{
    int ret = 1;

    size_t publickeylen = strlen(PUBLICKEYBASE64);
    const char *publickey = PUBLICKEYBASE64;

    const char *plaintext = PLAINTEXT;
    const size_t plaintextlen = strlen(plaintext);

    atchops_rsa_publickey publickeystruct;

    printf("populating public key struct..\n");
    ret = atchops_rsakey_populate_publickey(publickey, publickeylen, &publickeystruct);
    printf("atchops_rsa_populate_publickey returned: %d\n", ret);
    if(ret != 0)
        goto ret;

    const unsigned long ciphertextlen = 1024;
    unsigned char *ciphertext = calloc(ciphertextlen, sizeof(unsigned char));
    memset(ciphertext, 0, ciphertextlen);
    unsigned long ciphertextolen = 0;

    printf("encrypting...\n");
    ret = atchops_rsa_encrypt(publickeystruct, plaintext, plaintextlen, ciphertext, ciphertextlen, &ciphertextolen);
    printf("atchops_rsa_encrypt returned: %d\n", ret);
    if(ret != 0)
        goto ret;

    printf("ciphertext (base64 encoded): %s\n", ciphertext);
    printx(ciphertext, ciphertextolen);

    goto ret;

    ret:
    {
        return ret;
    }
}