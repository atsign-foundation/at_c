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
} atchops_rsa2048_publickey;

typedef struct {
    n_param *n;
    e_param *e;
    d_param *d;
    p_param *p;
    q_param *q;
} atchops_rsa2048_privatekey;

typedef enum {
    ATCHOPS_MD_NONE=0,    /**< None. */
    ATCHOPS_MD_MD5,       /**< The MD5 message digest. */
    ATCHOPS_MD_SHA1,      /**< The SHA-1 message digest. */
    ATCHOPS_MD_SHA224,    /**< The SHA-224 message digest. */
    ATCHOPS_MD_SHA256,    /**< The SHA-256 message digest. */
    ATCHOPS_MD_SHA384,    /**< The SHA-384 message digest. */
    ATCHOPS_MD_SHA512,    /**< The SHA-512 message digest. */
    ATCHOPS_MD_RIPEMD160,
} atchops_md_type;

void printx(unsigned char *data, size_t len);

void copy(unsigned char *dst, unsigned char *src, size_t len);

void atchops_rsa2048_publickey_init(atchops_rsa2048_publickey **publickeystruct);
void atchops_rsa2048_privatekey_init(atchops_rsa2048_privatekey **privatekeystruct);

void atchops_rsa2048_publickey_free(atchops_rsa2048_publickey *publickeystruct);
void atchops_rsa2048_privatekey_free(atchops_rsa2048_privatekey *privatekeystruct);

int atchops_rsa2048_populate_publickey(const unsigned char *publickeybase64, const size_t publickeybase64len, atchops_rsa2048_publickey *publickeystruct);

int atchops_rsa2048_populate_privatekey(const unsigned char *privatekeybase64, const size_t privatekeybase64len, atchops_rsa2048_privatekey *privatekeystruct);

int atchops_rsa2048_sign(atchops_rsa2048_privatekey *privatekeystruct, atchops_md_type mdtype, unsigned char **signature, size_t *signaturelen, const unsigned char *message, const size_t messagelen);

// todo
// int atchops_rsa2048_verify(atchops_rsa2048_publickey *publickeystruct, const unsigned char *signature, const size_t signaturelen, );

int atchops_rsa2048_encrypt(atchops_rsa2048_publickey *publickeystruct, const unsigned char *plaintext, const size_t plaintextlen, unsigned char *ciphertext, const size_t ciphertextlen, size_t *ciphertextolen);

int atchops_rsa2048_decrypt(atchops_rsa2048_privatekey *privatekeystruct, const unsigned char *ciphertext, const size_t ciphertextlen, unsigned char *plaintext, const size_t *plaintextlen, size_t *plaintextolen);

#ifdef __cplusplus
}
#endif
#endif