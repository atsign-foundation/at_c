
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "at_chops/rsa.h"
#include "at_chops/byteutil.h"

#define PUBLICKEYBASE64 "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAg3P7mefqZg2GNQPiEHYinmTYUcbbW2Ar9Wi5LCD/uRZNRiQJypbAQbpvk6fAo1wh5Ntp1kjPGHrIikUBVREItTkulobOOPVNaC5FUg86kQJ2Wk+ZyPaCIfrto7Gv+yn2DiKqjdYdexjmaKbMO90WSZ7yEmC2mq8bRQASD0PoG3RX1skhGkV1FvPbH4OEDuzMxHfGcCvCi3+BPcbgjLIT/dKe2zAHS5/fE9OK1bz+/FutJTF8M6LKQY8E+h2cQjTEn3RRJlcMp4rwq/0GNmm3mNY5EhUcamKiSWILG9a8nYzeIUafXmESCZk+J1yVu9QcmXP8Dokv+4KLv76/Y1RsqQIDAQAB"

int main()
{
    int ret = 1;

    size_t publickeylen = strlen(PUBLICKEYBASE64);
    const char *publickey = PUBLICKEYBASE64;

    const char *plaintext = "Hello, World!";
    const size_t plaintextlen = strlen(plaintext);

    atchops_rsa2048_publickey publickeystruct;

    printf("populating public key struct..\n");
    ret = atchops_rsa_populate_publickey(publickey, publickeylen, &publickeystruct);
    if(ret != 0)
        goto ret;

    const size_t ciphertextlen = 256;
    char *ciphertext = malloc(sizeof(unsigned char) * ciphertextlen + 1);
    size_t *ciphertextolen = malloc(sizeof(size_t));

    printf("encrypting...\n");
    ret = atchops_rsa2048_encrypt(publickeystruct, plaintext, plaintextlen, &ciphertext, ciphertextolen);
    if(ret != 0)
        goto ret;

    // add null terminator
    ciphertext[*ciphertextolen] = '\0';

    printf("ciphertext (base64 encoded): %s\n", ciphertext);
    printx(ciphertext, *ciphertextolen);

    goto ret;

    ret: 
    {
        return ret;
    }
}