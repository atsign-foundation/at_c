#pragma once

#ifdef BUILD_MBEDTLS
#ifdef __cplusplus
extern "C"
{
#endif

#include <ctype.h>

typedef struct n_param {
    size_t len;
    unsigned char *n;
} n_param;

typedef struct e_param {
    size_t len;
    unsigned char *e;
} e_param;

typedef struct d_param {
    size_t len;
    unsigned char *d;
} d_param;

typedef struct p_param {
    size_t len;
    unsigned char *p;
} p_param;

typedef struct q_param {
    size_t len;
    unsigned char *q;
} q_param;

typedef struct {
    n_param *n;
    e_param *e;
} RSA2048_PublicKey;

typedef struct {
    n_param *n;
    e_param *e;
    d_param *d;
    p_param *p;
    q_param *q;
} RSA2048_PrivateKey;

void printx(unsigned char *data, size_t len);

void copy(unsigned char *dst, unsigned char *src, size_t len);

void atchops_rsa2048_publickey_init(RSA2048_PublicKey **publickeystruct);
void atchops_rsa2048_privatekey_init(RSA2048_PrivateKey **privatekeystruct);

void atchops_rsa2048_publickey_free(RSA2048_PublicKey *publickeystruct);
void atchops_rsa2048_privatekey_free(RSA2048_PrivateKey *privatekeystruct);

int atchops_rsa2048_populate_publickey(const unsigned char *publickeybase64, const size_t publickeybase64len, RSA2048_PublicKey *publickeystruct);

int atchops_rsa2048_populate_privatekey(const unsigned char *privatekeybase64, const size_t privatekeybase64len, RSA2048_PrivateKey *privatekeystruct);

int atchops_rsa2048_encrypt(RSA2048_PublicKey *publickeystruct, const unsigned char *plaintext, const size_t plaintextlen, unsigned char *ciphertext, const size_t ciphertextlen, size_t *ciphertextolen);

int atchops_rsa2048_decrypt(RSA2048_PrivateKey *privatekeystruct, const unsigned char *ciphertext, const size_t ciphertextlen, unsigned char *plaintext, const size_t *plaintextlen, size_t *plaintextolen);

#ifdef __cplusplus
}
#endif
#endif