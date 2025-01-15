#ifndef ATCHOPS_RSA_H
#define ATCHOPS_RSA_H
#ifdef __cplusplus
extern "C" {
#endif

#include "atchops/constants.h" // IWYU pragma: keep
#include "atchops/sha.h"
#include <atchops/platform.h> // IWYU pragma: keep
#include <stddef.h>

/**
    * @brief Sign a hashed messaged with an Edwards curve private key
    *
    * @param private_key the private key struct to use for signing, see atchops_ed25519_key_populate_private_key
    * @param message the message to sign
    * @param message_len the length of the message, most people use strlen() to find this length
    * @param signature the signature buffer to populate, must be pre-allocated. Signature size will correspond to the
    * specified hashing algorithm (e.g., this function expects `signature` to be a buffer of 64 bytes allocated because a
    * Ed25519 key is used, which corresponds to a 256-bit signature)
    * @return int 0 on success
    */
int atchops_ed25519_sign(const atchops_ed25519_key_private_key *private_key, const unsigned char *message,
                         const size_t message_len, unsigned char *signature);

/**
* @brief Verify a signature with an Edwards curve public key
*
* @param public_key the public key to use for verification, see atchops_ed25519_key_populate_public_key
* @param message the original message to hash, in bytes
* @param message_len the length of the original message, most people use strlen() to find this length
* @param signature the signature to verify, expected to be the same length as the key size (e.g. 64 bytes for Ed25519)
* @return int 0 on success
*/
int atchops_ed25519_verify(const atchops_ed25519_key_public_key *public_key, const unsigned char *message,
                           const size_t message_len, const unsigned char *signature);

/**
* @brief Encrypt bytes with an Edwards curve public key
*
* @param public_key the public key struct to use for encryption, see atchops_ed25519_key_populate_public_key
* @param plaintext the plaintext to encrypt, in bytes
* @param plaintext_len the length of the plaintext, most people use strlen() to find this length
* @param ciphertext the ciphertext buffer to populate, must be 256 bytes long
* @return int 0 on success
*/
int atchops_ed25519_encrypt(const atchops_ed25519_key_public_key *public_key, const unsigned char *plaintext,
                            const size_t plaintext_len, unsigned char *ciphertext);

/**
* @brief Decrypt bytes with an Edwards curve private key
*
* @param private_key the private key struct to use for decryption, see atchops_ed25519_key_populate_private_key
* @param ciphertext the ciphertext to decrypt, in bytes
* @param ciphertext_len the length of the ciphertext, most people use strlen() to find this length
* @param plaintext the plaintext buffer to populate, must be pre-allocated. Plaintext size will correspond to the
* specified hashing algorithm (e.g., this function expects `plaintext` to be a buffer of 64 bytes allocated because a
* Ed25519 key is used, which corresponds to a 256-bit signature)
* @return int 0 on success
*/
int atchops_ed25519_decrypt(const atchops_ed25519_key_private_key *private_key, const unsigned char *ciphertext,
                            const size_t ciphertext_len, unsigned char *plaintext);

#ifdef __cplusplus
}
#endif
#endif