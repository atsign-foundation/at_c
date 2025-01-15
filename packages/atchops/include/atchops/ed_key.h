#ifndef ATCHOPS_ED_KEY_H
#define ATCHOPS_ED_KEY_H
#ifdef __cplusplus
extern "C" {
#endif

#include <atchops/platform.h> // IWYU pragma: keep
#include <stdbool.h>
#include <stddef.h>

/**
*
* Note to whatever brave soul ventures here:
* I was using the following resources for the implementation of Ed25519 (if any url is not found, use archive.org):
* https://www.oryx-embedded.com/doc/ed25519_8c_source.html
* https://eprint.iacr.org/2020/823.pdf
* Most helpful: https://bibliotecadigital.ipb.pt/bitstream/10198/24067/1/Nakai_Eduardo.pdf
*/

/**
* @brief Edwards curve key parameter struct
*
* I wanted to write a note to clarify that public key only has the public key point (its single fixed-length val),
* and private key has the private key scalar and the public key point due to the simpler
* key structure of Ed25519 keys. There is no need for independent components unless we
* want to use modular arithmetic for the public key point which is not necessary for Ed25519.
*/
typedef struct atchops_ed25519_key_param {
    size_t len;                     // Length of the parameter in bytes
    unsigned char *value;           // Byte array representing the parameter
    bool is_initialized : 1;        // Whether the parameter is initialized
} atchops_ed25519_key_param;

typedef struct atchops_ed25519_key_public_key {
    atchops_ed25519_key_param A;    // Public key point (32 bytes/256 bits)
} atchops_ed25519_key_public_key;

typedef struct atchops_ed25519_key_private_key {
    atchops_ed25519_key_param k;    // Private key scalar (32 bytes/256 bits)
    atchops_ed25519_key_param A;    // Public key point (derived from private key, 32 bytes)
} atchops_ed25519_key_private_key;

// Public key management functions
void atchops_ed25519_key_public_key_init(atchops_ed25519_key_public_key *public_key);
void atchops_ed25519_key_public_key_free(atchops_ed25519_key_public_key *public_key);

// Private key management functions
void atchops_ed25519_key_private_key_init(atchops_ed25519_key_private_key *private_key);
void atchops_ed25519_key_private_key_free(atchops_ed25519_key_private_key *private_key);

/** 
* @brief Generate a new Ed25519 key pair (public and private)
* 
* @param public_key the public key struct to populate
* @param private_key the private key struct to populate
* @return int 0 on success
*/
int atchops_ed25519_key_generate(atchops_ed25519_key_public_key *public_key, 
                                 atchops_ed25519_key_private_key *private_key);

// Serialization and deserialization
/**
* @brief Serialize/deserialize an Ed25519 public key to a byte array
*
* @param public_key/private_key the public/private key struct to serialize
* @param out the byte array to populate with the serialized public/private key
* @return int 0 on success
*/
int atchops_ed25519_key_public_key_serialize(const atchops_ed25519_key_public_key *public_key, unsigned char *out);
int atchops_ed25519_key_public_key_deserialize(atchops_ed25519_key_public_key *public_key, const unsigned char *in);

int atchops_ed25519_key_private_key_serialize(const atchops_ed25519_key_private_key *private_key, unsigned char *out);
int atchops_ed25519_key_private_key_deserialize(atchops_ed25519_key_private_key *private_key, const unsigned char *in);

// Key usage
/**
* @brief Sign a hashed message with an Ed25519 private key
*
* @param message the message to sign
* @param message_len the length of the message, most people use strlen() to find this length
* @param private_key the private key struct to use for signing
* @param signature_out the signature buffer to populate, must be pre-allocated. Signature size will correspond to the
* specified hashing algorithm (e.g., this function expects `signature` to be a buffer of 64 bytes allocated because a
* Ed25519 key is used, which corresponds to a 256-bit signature)
* @return int 0 on success
*/
int atchops_ed25519_sign(const unsigned char *message, size_t message_len, 
                         const atchops_ed25519_key_private_key *private_key, 
                         unsigned char *signature_out);

/**
* @brief Verify a signature with an Ed25519 public key
*
* @param message the original message to hash, in bytes
* @param message_len the length of the original message, most people use strlen() to find this length
* @param signature the signature to verify, expected to be the same length as the key size (e.g. 64 bytes for Ed25519)
* @param public_key the public key to use for verification
* @return int 0 on success
*/
int atchops_ed25519_verify(const unsigned char *message, size_t message_len, 
                           const unsigned char *signature, 
                           const atchops_ed25519_key_public_key *public_key);

/**
* @brief perform r modulo L for Ed25519
*
* @param r_mod_l the buffer to populate with the result
* @param r the buffer to perform the operation on
* @return int 0 on success
*/
int atchops_ed25519_mod_l(unsigned char *r_mod_l, const unsigned char *r);

/**
* @brief encode a point for Ed25519
*
* @param encoded_point the buffer to populate with the encoded point
* @param point the point to encode
* @return int 0 on success
*/
int atchops_ed25519_encode_point(unsigned char *encoded_point, const unsigned char *point);

/**
* @brief Compute the point R = [r]B
*
* @param R the buffer to populate with the result
* @param r the buffer to perform the operation on
* @return int 0 on success
*/

int atchops_ed25519_scalar_mult_base(unsigned char *R, const unsigned char *r);


#ifdef __cplusplus
}
#endif
#endif