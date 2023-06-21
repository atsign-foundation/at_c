#pragma once

#ifdef BUILD_MBEDTLS
#ifdef __cplusplus
extern "C"
{
#endif

#include <ctype.h>

typedef struct rsa_param {
    size_t len;
    unsigned char *value; // hex byte array of the number
}

typedef struct {
    rsa_param n_param; // modulus
    rsa_param e_param; // public exponent
} atchops_rsa2048_publickey;

typedef struct {
    rsa_param n_param; // modulus
    rsa_param e_param; // public exponent
    rsa_param d_param; // private exponent
    rsa_param p_param; // prime 1
    rsa_param q_param; // prime 2
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

/**
 * @brief Populate a public key struct from a base64 string
 * 
 * @param publickeybase64 a base64 string representing an RSA 2048 Public Key
 * @param publickeybase64len the length of the base64 string
 * @param publickeystruct the public key struct to populate
 * @return int 0 on success
 */
int atchops_rsa_populate_publickey(const unsigned char *publickeybase64, const size_t publickeybase64len, atchops_rsa2048_publickey *publickeystruct);

/**
 * @brief Populate a private key struct from a base64 string
 * 
 * @param privatekeybase64 the base64 string representing an RSA 2048 Private Key
 * @param privatekeybase64len the length of the base64 string
 * @param privatekeystruct the private key struct to populate
 * @return int 0 on success
 */
int atchops_rsa_populate_privatekey(const unsigned char *privatekeybase64, const size_t privatekeybase64len, atchops_rsa2048_privatekey *privatekeystruct);

/**
 * @brief Sign a message with an RSA 2048 Private Key
 * 
 * @param privatekeystruct the private key struct to use for signing
 * @param mdtype the message digest type to use
 * @param signature the signature to populate. Pass in a pointer to a pointer to an unsigned char array. The pointer will be reassigned to the newly allocated array.
 * @param signaturelen  the output length of the signature
 * @param message the message to sign
 * @param messagelen the length of the message
 * @return int 0 on success
 */
int atchops_rsa_sign(atchops_rsa2048_privatekey privatekeystruct, atchops_md_type mdtype, unsigned char **signature, size_t *signaturelen, const unsigned char *message, const size_t messagelen);

// todo
// int atchops_rsa2048_verify(atchops_rsa2048_publickey *publickeystruct, const unsigned char *signature, const size_t signaturelen, );

/**
 * @brief Encrypt plain text with a RSA 2048 Public Key
 * 
 * @param publickeystruct 
 * @param plaintext 
 * @param plaintextlen 
 * @param ciphertext 
 * @param ciphertextlen 
 * @param ciphertextolen 
 * @return int 
 */
int atchops_rsa2048_encrypt(atchops_rsa2048_publickey *publickeystruct, const unsigned char *plaintext, const size_t plaintextlen, unsigned char *ciphertext, const size_t ciphertextlen, size_t *ciphertextolen);

// todo
// int atchops_rsa2048_decrypt(atchops_rsa2048_privatekey *privatekeystruct, const unsigned char *ciphertext, const size_t ciphertextlen, unsigned char *plaintext, const size_t *plaintextlen, size_t *plaintextolen);

#ifdef __cplusplus
}
#endif
#endif