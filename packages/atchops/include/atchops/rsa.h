#ifndef ATCHOPS_RSA_H
#define ATCHOPS_RSA_H

#include "atchops/constants.h"
#include "atchops/rsa_key.h"
#include <stddef.h>

/**
 * @brief Sign a hashed message with an RSA private key
 *
 * @param private_key the private key struct to use for signing, see atchops_rsa_key_populate_private_key
 * @param md_type the hash type to use, see atchops_md_type, e.g. ATCHOPS_MD_SHA256. The message will be hashed with this
 * algorithm before signing
 * @param message the message to sign
 * @param message_len the length of the message, most people use strlen() to find this length
 * @param signature the signature buffer to populate, must be pre-allocated. Signature size will correspond to the
 * specified hashing algorithm (e.g., this function expects `signature` to be a buffer of 256 bytes allocated because a
 * RSA-2048 key is used, which corresponds to a 2048-bit signature)
 * @return int 0 on success
 */
int atchops_rsa_sign(const atchops_rsa_key_private_key *private_key, const atchops_md_type md_type,
                     const unsigned char *message, const size_t message_len, unsigned char *signature);

/**
 * @brief Verify a signature with an RSA public key
 *
 * @param public_key the public key to use for verification, see atchops_rsa_key_populate_public_key
 * @param md_type the hash type to use, see atchops_md_type, e.g. ATCHOPS_MD_SHA256
 * @param message the original message to hash, in bytes
 * @param message_len the length of the original message, most people use strlen() to find this length
 * @param signature the signature to verify, expected to be the same length as the key size (e.g. 256 bytes for 2048 RSA
 * modulus)
 * @return int 0 on success
 */
int atchops_rsa_verify(const atchops_rsa_key_public_key *public_key, const atchops_md_type md_type,
                       const unsigned char *message, const size_t message_len, unsigned char *signature);

/**
 * @brief Encrypt bytes with an RSA public key
 *
 * @param public_key the public key struct to use for encryption, see atchops_rsa_key_populate_public_key
 * @param plaintext the plaintext to encrypt, in bytes
 * @param plaintext_len the length of the plaintext, most people use strlen() to find this length
 * @param ciphertext the ciphertext buffer to populate, assumed to be 256 bytes long for 2048 RSA modulus
 * @return int 0 on success
 */
int atchops_rsa_encrypt(const atchops_rsa_key_public_key *public_key, const unsigned char *plaintext,
                        const size_t plaintext_len, unsigned char *ciphertext);

/**
 * @brief Decrypt bytes with an RSA private key
 *
 * @param private_key the private key struct to use for decryption, see atchops_rsa_key_populate_private_key
 * @param ciphertext the ciphertext to decrypt, in bytes
 * @param ciphertext_len the length of the ciphertext, should be the same as the key size (e.g. 256 bytes for 2048 RSA
 * modulus)
 * @param plaintext the plaintext buffer to populate
 * @param plaintext_size the size of the plaintext buffer (allocated size)
 * @param plaintext_len the written length of the plaintext buffer after decryption operation has completed
 * @return int 0 on success
 */
int atchops_rsa_decrypt(const atchops_rsa_key_private_key *private_key, const unsigned char *ciphertext,
                        const size_t ciphertext_len, unsigned char *plaintext, const size_t plaintext_size,
                        size_t *plaintext_len);

/**
 * @brief generate an RSA keypair
 *
 * @param public_key the public key struct to populate, should be initialized first
 * @param private_key the private key struct to populate, should be initialized first
 * @param keysize the size of the key to generate, e.g. 2048
 */
int atchops_rsa_generate(atchops_rsa_key_public_key *public_key, atchops_rsa_key_private_key *private_key,
                         const atchops_md_type md_type);

#endif
