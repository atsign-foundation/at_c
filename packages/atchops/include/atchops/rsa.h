#ifndef ATCHOPS_RSA_H
#define ATCHOPS_RSA_H

#include "atchops/rsakey.h"
#include "atchops/sha.h"
#include <mbedtls/md.h>

/**
 * @brief Sign a message with an RSA private key
 *
 * @param privatekey the private key struct to use for signing, see atchops_rsakey_populate_privatekey
 * @param mdtype the hash type to use, see atchops_md_type, e.g. ATCHOPS_MD_SHA256
 * @param message the message to sign
 * @param messagelen the length of the message, most people use strlen() to find this length
 * @param signature the signature buffer to populate
 * @param signaturelen the length of the signature buffer
 * @param signatureolen the length of the signature buffer after signing
 * @return int 0 on success
 */
int atchops_rsa_sign(atchops_rsakey_privatekey privatekey, mbedtls_md_type_t mdtype, const unsigned char *message,
                     const unsigned long messagelen, unsigned char *signaturebase64,
                     const unsigned long signaturebase64len, unsigned long *signaturebase64olen);

/**
 * @brief Verify a signature with an RSA public key
 *
 * @param publickey the public key to use for verification, see atchops_rsakey_populate_publickey
 * @param mdtype the hash type to use, see atchops_md_type, e.g. ATCHOPS_MD_SHA256
 * @param signature the signature to verify
 * @param signaturelen the length of the signature, most people use strlen() to find this length
 * @param result 1 if the signature is valid, 0 if the signature is invalid
 * @return int 0 on success
 */
int atchops_rsa_verify(atchops_rsakey_publickey publickey, mbedtls_md_type_t mdtype, const unsigned char *signature,
                       const unsigned long signaturelen, int *result);

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
int atchops_rsa_encrypt(atchops_rsakey_publickey publickey, const unsigned char *plaintext,
                        const unsigned long plaintextlen, unsigned char *ciphertextbase64,
                        const unsigned long ciphertextbase64len, unsigned long *ciphertextbase64olen);

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
int atchops_rsa_decrypt(atchops_rsakey_privatekey privatekeystruct, const unsigned char *ciphertextbase64,
                        const unsigned long ciphertextbase64len, unsigned char *plaintext,
                        const unsigned long plaintextlen, unsigned long *plaintextolen);

/**
 * @brief generate an RSA keypair
 *
 * @param publickey the public key struct to populate, should be initialized first
 * @param privatekey the private key struct to populate, should be initialized first
 * @param keysize the size of the key to generate, e.g. 2048
 */
int atchops_rsa_generate(atchops_rsakey_publickey *publickey, atchops_rsakey_privatekey *privatekey,
                         const unsigned int keysize);

#endif