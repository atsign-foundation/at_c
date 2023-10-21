#pragma once

#include "sha.h"

typedef struct rsakey_param
{
    unsigned long len;    // length of the number in bytes
    unsigned char *value; // hex byte array of the number
} rsakey_param;

typedef struct atchops_rsa_publickey
{
    rsakey_param n; // modulus
    rsakey_param e; // public exponent
} atchops_rsa_publickey;

typedef struct atchops_rsa_privatekey
{
    rsakey_param n; // modulus
    rsakey_param e; // public exponent
    rsakey_param d; // private exponent
    rsakey_param p; // prime 1
    rsakey_param q; // prime 2
} atchops_rsa_privatekey;

/**
 * @brief Populate a public key struct from a base64 string
 *
 * @param publickeybase64 a base64 string representing an RSA 2048 Public Key
 * @param publickeybase64len the length of the base64 string
 * @param publickeystruct the public key struct to populate
 * @return int 0 on success
 */
int atchops_rsakey_populate_publickey(const char *publickeybase64, const unsigned long publickeybase64len, atchops_rsa_publickey *publickeystruct);

/**
 * @brief Populate a private key struct from a base64 string
 *
 * @param privatekeybase64 the base64 string representing an RSA 2048 Private Key
 * @param privatekeybase64len the length of the base64 string
 * @param privatekeystruct the private key struct to populate
 * @return int 0 on success
 */
int atchops_rsakey_populate_privatekey(const char *privatekeybase64, const unsigned long privatekeybase64len, atchops_rsa_privatekey *privatekeystruct);

/**
 * @brief Sign a message with an RSA private key
 *
 * @param privatekeystruct the private key struct to use for signing, see atchops_rsakey_populate_privatekey
 * @param mdtype the hash type to use, see atchops_md_type, e.g. ATCHOPS_MD_SHA256
 * @param message the message to sign
 * @param messagelen the length of the message, most people use strlen() to find this length
 * @param signature the signature buffer to populate
 * @param signaturelen the length of the signature buffer
 * @param signatureolen the length of the signature buffer after signing
 * @return int 0 on success
 */
int atchops_rsa_sign(atchops_rsa_privatekey privatekeystruct, atchops_md_type mdtype, const unsigned char *message, const unsigned long messagelen, unsigned char *signature, const unsigned long signaturelen, unsigned long *signatureolen);

/**
 * @brief Encrypt bytes with an RSA public key
 *
 * @param publickeystruct the public key struct to use for encryption, see atchops_rsakey_populate_publickey
 * @param plaintext the plaintext to encrypt
 * @param plaintextlen the length of the plaintext, most people use strlen() to find this length
 * @param ciphertext the ciphertext buffer to populate
 * @param ciphertextlen the length of the ciphertext buffer
 * @param ciphertextolen the length of the ciphertext buffer after encryption
 * @return int 0 on success
 */
int atchops_rsa_encrypt(atchops_rsa_publickey publickeystruct, const unsigned char *plaintext, const unsigned long plaintextlen, unsigned char *ciphertext, const unsigned long ciphertextlen, unsigned long *ciphertextolen);

/**
 * @brief Decrypt bytes with an RSA private key
 *
 * @param privatekeystruct the private key struct to use for decryption, see atchops_rsakey_populate_privatekey
 * @param ciphertextbase64 the ciphertext to decrypt, base64 encoded
 * @param ciphertextbase64len the length of the ciphertext, most people use strlen() to find this length
 * @param plaintext the plaintext buffer to populate
 * @param plaintextlen the length of the plaintext buffer
 * @param plaintextolen the length of the plaintext buffer after decryption
 * @return int 0 on success
 */
int atchops_rsa_decrypt(atchops_rsa_privatekey privatekeystruct, const unsigned char *ciphertextbase64, const unsigned long ciphertextbase64len, unsigned char *plaintext, const unsigned long plaintextlen, unsigned long *plaintextolen);
