#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include "at_chops/rsa2048.h"
#include "at_chops/base64.h"

int main()
{
    int ret;
    const unsigned char *privatekeybase64 = "MIIEvAIBADANBgkqhkiG9w0BAQEFAASCBKYwggSiAgEAAoIBAQCy64Pzy9ZDdm6e96z3DmjektD7sKUo40Ax+1VD12Ksm3pUPTGDkM3Nf4Sp2ATcy6ZbCRHSEWtx7dPfC/H1p7yS9KOVLtAmx8aT0SNiT+WGsclshI/n/XP+jCjxrpYwf4ntgX2i6p6hlo/ZiW8i3+Ayyhw8uYuVMUyMHv70EaoTN0+N5QF9l74LkLYL7cXyfZayDPTZJxbLF2WEoQz4ZWJhgFk40EeBw03jiLg/T0hw1gbS0z97HhZs/QPtTaDR9EJYq27eZagRFZ6em7esrjjTpmGaTJmtZjEomV6o/EOtdvImRe1tViI22DWGAKi87BBGXR5Zr3xoRXPSypHLqLsNAgMBAAECggEAatzd//QEMmD/KzVU+m6B1kYsSde0nZo1kmTCBXYUenGWe8/cze7j7NQ4AVWDefiskHz3Rteeq/pXbEXvK0EXEVLKjWTbb/4sLcdg8ew0c+GmI4l9hhtMd4FxRwB2tdrHH7MSvgaR3oNVwaEjXtoGR2+Ns/tCUkaSqLIupsoSIc0Mj07Teq7SZvAe++oMyNgkyArR509oSG0GQFQp706VgLaUVrvtlMEXvtGB0pcn/y1Axz/l9VvYpojYp7MqSwVU6R4GWxjrn4JXCVQrh48VmuJS83i2oqFgbAXD2KyNjjkoW3Z26uhfJ0qgN2PeQgMYH06gNhfEYOAGTI8HgtfChQKBgQDc7xIYG0IchAX/0lds4yUXRRF9wEjZmsvaf6LZPEs97/z11cAbTp41zlppCqpGL0md/lTwFVwsmGuZNob999sGKi7A6mM2sBj+QiBoHACvl2e167O72eFYqyXtJwDH5XOA5JMHbc6GJpSeVE29UnIgq1czgp3DtapQRX3BOPMRYwKBgQDPUVjZJERK5N9ccs59gjyKiu6e60m42AVjpvaCWbqPSZXTEhGM8X9OJNsdZufRoMi6tYctXGthiB4HOoV1E5ACvJxgWpOTmbqqbBDA5pQPrJ4eRdigHjGnrAWdsJ+3smMbhk/6Ai00gmqwz8rv7eyGSY+dwOem/vPoJOrlRFFkzwKBgH+IhbJiscQSNgBZpFvXtwZ6uUEU6Tir0bccbJ3n3ysuyKAENnPM6yj2KFxwaqA/FcjdEpzQR7f6eEomHsCl/cnOOdTkuEbOWm8TLu/KEl9KD/UEzWjHufxcN3VxSVMa0ZT63SCxs0DfLnVDBukdmYHgRmMWqAlcaacSpigOvskvAoGADVikSp5OEzA2vOHbLzNCKH0XLX3iKhcmCatG9U9Hdk/7aDIilRs64dH3lSX5yIH8SiDDigUIGKhFnpuC2e2feL2hp4ZNN9ROswfv8Csn3vZy22oNrwkikzO8zNEBBzdhr/Tukx6uwFGhAq7t1pJPhrmXmEVB5HtHQmuV/5ptTvsCgYA5d5L3hO3+1Na4C6xj8luQXFhkSLNe0rwoe16OLjcyzcnhlb2KKA8rORGP28s1JcCL4Htasf0YzCkOJ/jR28GzX/0qvWu0hBSilV2mCAqwQ1fvZx0L4quJznkAhJPMZ+oag8o1LlQiJGgnhsIMbDLZApKh3NuYlTmdqo20FfkZkg==";
    size_t privatekeybase64len = strlen(privatekeybase64);
    
    atchops_rsa2048_privatekey *privatekeystruct;
    atchops_rsa2048_privatekey_init(&privatekeystruct);

    ret = atchops_rsa2048_populate_privatekey(privatekeybase64, privatekeybase64len, privatekeystruct);
    if (ret != 0) goto ret;
    // printf("ret: %d\n", ret);

    // // print n e d p q lengths
    // printf("n len: %lu\n", privatekeystruct->n->len);
    // printf("e len: %lu\n", privatekeystruct->e->len);
    // printf("d len: %lu\n", privatekeystruct->d->len);
    // printf("p len: %lu\n", privatekeystruct->p->len);
    // printf("q len: %lu\n", privatekeystruct->q->len);

    // print n e d p q
    // printf("n: ");
    // printx(privatekeystruct->n->n, privatekeystruct->n->len);
    // printf("e: ");
    // printx(privatekeystruct->e->e, privatekeystruct->e->len);
    // printf("d: ");
    // printx(privatekeystruct->d->d, privatekeystruct->d->len);
    // printf("p: ");
    // printx(privatekeystruct->p->p, privatekeystruct->p->len);
    // printf("q: ");
    // printx(privatekeystruct->q->q, privatekeystruct->q->len);

    // atchops_rsa2048_privatekey_free(privatekeystruct);

    // =====
    // public key test
    // ====

    const unsigned char *publickeybase64 = "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAsuuD88vWQ3Zunves9w5o3pLQ+7ClKONAMftVQ9dirJt6VD0xg5DNzX+EqdgE3MumWwkR0hFrce3T3wvx9ae8kvSjlS7QJsfGk9EjYk/lhrHJbISP5/1z/owo8a6WMH+J7YF9ouqeoZaP2YlvIt/gMsocPLmLlTFMjB7+9BGqEzdPjeUBfZe+C5C2C+3F8n2Wsgz02ScWyxdlhKEM+GViYYBZONBHgcNN44i4P09IcNYG0tM/ex4WbP0D7U2g0fRCWKtu3mWoERWenpu3rK4406ZhmkyZrWYxKJleqPxDrXbyJkXtbVYiNtg1hgCovOwQRl0eWa98aEVz0sqRy6i7DQIDAQAB";

    size_t publickeybase64len = strlen(publickeybase64);

    atchops_rsa2048_publickey *publickeystruct;
    atchops_rsa2048_publickey_init(&publickeystruct);

    ret = atchops_rsa2048_populate_publickey(publickeybase64, publickeybase64len, publickeystruct);
    if (ret != 0) goto ret;

    // print n e lengths
    // printf("n len: %lu\n", publickeystruct->n->len);
    // printf("e len: %lu\n", publickeystruct->e->len);

    // print n e
    // printf("n: ");
    // printx(publickeystruct->n->n, publickeystruct->n->len);
    // printf("e: ");
    // printx(publickeystruct->e->e, publickeystruct->e->len);

    // atchops_rsa2048_publickey_free(publickeystruct);


    // =====
    // encrypt test
    // ====

    const unsigned char* plaintext = "lemonade";
    size_t plaintextlen = strlen(plaintext);

    const size_t ciphertextlen = 1000;
    unsigned char *ciphertext = malloc(sizeof(unsigned char) * ciphertextlen);
    size_t *ciphertextolen = malloc(sizeof(size_t));

    ret = atchops_rsa2048_encrypt(publickeystruct, plaintext, plaintextlen, ciphertext, ciphertextlen, ciphertextolen);
    if (ret != 0) goto ret;

    // =====
    // signing
    // =====

    unsigned char *signature;
    size_t *signaturelen;
    const unsigned char *message = "_4a160d33-0c63-4800-bee0-ee254752f8c8@jeremy_0:6c987cc1-0dde-4ba1-af56-a9677086182";
    const size_t messagelen = strlen(message);

    ret = atchops_rsa2048_sign(privatekeystruct, SHA256, &signature, signaturelen, message, messagelen);
    if(ret != 0) goto ret;

    // TODO signature to use mpi_ constant A buffer length of #MBEDTLS_MPI_MAX_SIZE is always safe.

    // unsigned char *signature_str = malloc(sizeof(unsigned char) * ((*signaturelen) + 1));
    // memcpy(signature_str, signature, *signaturelen);
    // signature_str[*signaturelen] = '\0';
    // printf("Signature: %s\n", signature_str);
    
    goto ret;
        
    ret: {
        return ret;
    }
}