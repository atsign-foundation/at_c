#pragma once

#include <stddef.h>
#include <ctype.h>
#include "sha.h"

typedef struct {
    size_t len;
    unsigned char *value; // hex byte array of the number
} rsa_param;

typedef struct {
    rsa_param n_param; // modulus
    rsa_param e_param; // public exponent
} atchops_rsa_publickey;

typedef struct {
    rsa_param n_param; // modulus
    rsa_param e_param; // public exponent
    rsa_param d_param; // private exponent
    rsa_param p_param; // prime 1
    rsa_param q_param; // prime 2
} atchops_rsa_privatekey;

/**
 * @brief Populate a public key struct from a base64 string
 *
 * @param publickeybase64 a base64 string representing an RSA 2048 Public Key
 * @param publickeybase64len the length of the base64 string
 * @param publickeystruct the public key struct to populate
 * @return int 0 on success
 */
int atchops_rsa_populate_publickey(const char *publickeybase64, const size_t publickeybase64len, atchops_rsa_publickey *publickeystruct);

/**
 * @brief Populate a private key struct from a base64 string
 *
 * @param privatekeybase64 the base64 string representing an RSA 2048 Private Key
 * @param privatekeybase64len the length of the base64 string
 * @param privatekeystruct the private key struct to populate
 * @return int 0 on success
 */
int atchops_rsa_populate_privatekey(const char *privatekeybase64, const size_t privatekeybase64len, atchops_rsa_privatekey *privatekeystruct);

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
int atchops_rsa_sign(atchops_rsa_privatekey privatekeystruct, atchops_md_type mdtype, unsigned char **signature, size_t *signaturelen, const unsigned char *message, const size_t messagelen);

/**
 * @brief Encrypt a string of text with an RSA 2048 Public Key
 * 
 * @param publickeystruct the public key struct to use for encryption, must be populated using atchops_rsa_populate_publickey
 * @param plaintext the plain text to encrypt
 * @param plaintextlen the length of the plain text
 * @param ciphertext the ciphertext to populate. Pass in a pointer to a pointer to a char array. The pointer will be reassigned to the newly allocated array. Assumption is enough space is allocated for the ciphertext.
 * @param ciphertextolen the output length of the ciphertext
 * @return int 0 on success
 */
int atchops_rsa_encrypt(atchops_rsa_publickey publickeystruct, const char *plaintext, const size_t plaintextlen, char **ciphertext, size_t *ciphertextolen);

/**
 * @brief Decrypt a string of text with an RSA 2048 Private Key
 * 
 * @param privatekeystruct the private key struct to use for decryption, must be populated using atchops_rsa_populate_privatekey
 * @param ciphertextbase64encoded the base64 encoded string ciphertext to decrypt 
 * @param ciphertextbase64encodedlen the length of the base64 encoded string
 * @param plaintext the plaintext to populate. Pass in a pointer to a pointer to a char array. The pointer will be reassigned to the newly allocated array. Assumption is enough space is allocated for the plaintext.
 * @param plaintextolen the output length of the plaintext
 * @return int 0 on success
 */
int atchops_rsa_decrypt(atchops_rsa_privatekey privatekeystruct, const char *ciphertextbase64encoded, const size_t ciphertextbase64encodedlen, char **plaintext, size_t *plaintextolen);
