#ifndef ATCHOPS_RSA_H
#define ATCHOPS_RSA_H

#include "atchops/rsakey.h"
#include <mbedtls/md.h>
#include <stddef.h>

/**
 * @brief Sign a message with an RSA private key
 *
 * @param privatekey the private key struct to use for signing, see atchops_rsakey_populate_privatekey
 * @param mdtype the hash type to use, see atchops_md_type, e.g. ATCHOPS_MD_SHA256
 * @param message the message to sign
 * @param messagelen the length of the message, most people use strlen() to find this length
 * @param signature the signature buffer to populate, must be pre-allocated. Signature size will correspond to the
 * specified hashing algorithm (e.g., this function expects `signature` to be a buffer of 32 bytes allocated, if using
 * ATCHOPS_MD_SHA256 (256 bits = 32 bytes)) .
 * @return int 0 on success
 */
int atchops_rsa_sign(const atchops_rsakey_privatekey privatekey, const mbedtls_md_type_t mdtype,
                     const unsigned char *message, const size_t messagelen, unsigned char *signature);

/**
 * @brief Verify a signature with an RSA public key
 *
 * @param publickey the public key to use for verification, see atchops_rsakey_populate_publickey
 * @param mdtype the hash type to use, see atchops_md_type, e.g. ATCHOPS_MD_SHA256
 * @param message the original message to hash, in bytes
 * @param messagelen the length of the original message, most people use strlen() to find this length
 * @param signature the signature to verify, expected to be the same length as the key size (e.g. 256 bytes for 2048 RSA modulus)
 * @return int 0 on success
 */
int atchops_rsa_verify(const atchops_rsakey_publickey publickey, const mbedtls_md_type_t mdtype, const unsigned char *message,
                       const size_t messagelen, unsigned char *signature);

/**
 * @brief Encrypt bytes with an RSA public key
 *
 * @param publickeystruct the public key struct to use for encryption, see atchops_rsakey_populate_publickey
 * @param plaintext the plaintext to encrypt, in bytes
 * @param plaintextlen the length of the plaintext, most people use strlen() to find this length
 * @param ciphertext the ciphertext buffer to populate
 * @param ciphertextsize the length of the ciphertext buffer
 * @param ciphertextlen the written length of the ciphertext buffer after encryption operation has completed, should be the same as the key size (e.g. 256 bytes for 2048 RSA modulus)
 * @return int 0 on success
 */
int atchops_rsa_encrypt(const atchops_rsakey_publickey publickey, const unsigned char *plaintext,
                        const size_t plaintextlen, unsigned char *ciphertext, const size_t ciphertextsize,
                        size_t *ciphertextlen);

/**
 * @brief Decrypt bytes with an RSA private key
 *
 * @param privatekey the private key struct to use for decryption, see atchops_rsakey_populate_privatekey
 * @param ciphertext the ciphertext to decrypt, in bytes
 * @param ciphertextlen the length of the ciphertext, should be the same as the key size (e.g. 256 bytes for 2048 RSA modulus)
 * @param plaintext the plaintext buffer to populate
 * @param plaintextsize the size of the plaintext buffer (allocated size)
 * @param plaintextlen the written length of the plaintext buffer after decryption operation has completed
 * @return int 0 on success
 */
int atchops_rsa_decrypt(const atchops_rsakey_privatekey privatekey, const unsigned char *ciphertext,
                        const size_t ciphertextlen, unsigned char *plaintext, const size_t plaintextsize,
                        size_t *plaintextlen);

/**
 * @brief generate an RSA keypair
 *
 * @param publickey the public key struct to populate, should be initialized first
 * @param privatekey the private key struct to populate, should be initialized first
 * @param keysize the size of the key to generate, e.g. 2048
 */
int atchops_rsa_generate(atchops_rsakey_publickey *publickey, atchops_rsakey_privatekey *privatekey,
                         const mbedtls_md_type_t mdtype);

#endif
