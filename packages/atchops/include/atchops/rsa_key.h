#ifndef ATCHOPS_RSA_KEY_H
#define ATCHOPS_RSA_KEY_H

#include <stdbool.h>
#include <stddef.h>

typedef struct atchops_rsa_key_param {
  size_t len;                    // length of the number in bytes
  unsigned char *value;           // hex byte array of the number
  bool _is_value_initialized : 1; // whether the value is allocated
} atchops_rsa_key_param;

typedef struct atchops_rsa_key_public_key {
  atchops_rsa_key_param n; // modulus
  atchops_rsa_key_param e; // public exponent
} atchops_rsa_key_public_key;

typedef struct atchops_rsa_key_private_key {
  atchops_rsa_key_param n; // modulus
  atchops_rsa_key_param e; // public exponent
  atchops_rsa_key_param d; // private exponent
  atchops_rsa_key_param p; // prime 1
  atchops_rsa_key_param q; // prime 2
} atchops_rsa_key_private_key;

void atchops_rsa_key_public_key_init(atchops_rsa_key_public_key *public_key);
void atchops_rsa_key_public_key_free(atchops_rsa_key_public_key *public_key);

void atchops_rsa_key_private_key_init(atchops_rsa_key_private_key *private_key);
void atchops_rsa_key_private_key_free(atchops_rsa_key_private_key *private_key);

/**
 * @brief Deep clone an atchops_rsa_key_public_key
 *
 * @param src the src from which to copy from
 * @param dst the new copy of key
 */
int atchops_rsa_key_public_key_clone(const atchops_rsa_key_public_key *src, atchops_rsa_key_public_key *dst);

/**
 * @brief Deep clone an atchops_rsa_key_private_key
 *
 * @param src the src from which to copy from
 * @param dst the new copy of key
 */
int atchops_rsa_key_private_key_clone(const atchops_rsa_key_private_key *src, atchops_rsa_key_private_key *dst);

/**
 * @brief Populate a public key struct from a base64 string
 *
 * @param public_key_struct the public key struct to populate
 * @param public_key_base64 a base64 string representing an RSA 2048 Public Key
 * @param public_key_base64_len the length of the base64 string
 * @return int 0 on success
 */
int atchops_rsa_key_populate_public_key(atchops_rsa_key_public_key *public_key_struct, const char *public_key_base64,
                                      const size_t public_key_base64_len);

/**
 * @brief Populate a private key struct from a base64 string
 *
 * @param private_key_struct the private key struct to populate
 * @param private_key_base64 the base64 string representing an RSA 2048 Private Key
 * @param private_key_base64_len the length of the base64 string
 * @return int 0 on success
 */
int atchops_rsa_key_populate_private_key(atchops_rsa_key_private_key *private_key_struct, const char *private_key_base64,
                                       const size_t privatekeprivate_key_base64_lenybase64len);

int atchops_rsa_key_public_key_set_ne(atchops_rsa_key_public_key *public_key, const unsigned char *n, const size_t n_len,
                                    const unsigned char *e, const size_t e_len);

bool atchops_rsa_key_public_key_is_n_initialized(atchops_rsa_key_public_key *public_key);
void atchops_rsa_key_public_key_set_n_initialized(atchops_rsa_key_public_key *public_key, const bool initialized);
int atchops_rsa_key_public_key_set_n(atchops_rsa_key_public_key *public_key, const unsigned char *n, const size_t n_len);
void atchops_rsa_key_public_key_unset_n(atchops_rsa_key_public_key *public_key);

bool atchops_rsa_key_public_key_is_e_initialized(atchops_rsa_key_public_key *public_key);
void atchops_rsa_key_public_key_set_e_initialized(atchops_rsa_key_public_key *public_key, const bool initialized);
int atchops_rsa_key_public_key_set_e(atchops_rsa_key_public_key *public_key, const unsigned char *e, const size_t e_len);
void atchops_rsa_key_public_key_unset_e(atchops_rsa_key_public_key *public_key);

int atchops_rsa_key_private_key_set_nedpq(atchops_rsa_key_private_key *private_key, const unsigned char *n,
                                        const size_t n_len, const unsigned char *e, const size_t e_len,
                                        const unsigned char *d, const size_t d_len, const unsigned char *p,
                                        const size_t p_len, const unsigned char *q, const size_t q_len);

bool atchops_rsa_key_private_key_is_n_initialized(atchops_rsa_key_private_key *private_key);
void atchops_rsa_key_private_key_set_n_initialized(atchops_rsa_key_private_key *private_key, const bool initialized);
int atchops_rsa_key_private_key_set_n(atchops_rsa_key_private_key *private_key, const unsigned char *n, const size_t n_len);
void atchops_rsa_key_private_key_unset_n(atchops_rsa_key_private_key *private_key);

bool atchops_rsa_key_private_key_is_e_initialized(atchops_rsa_key_private_key *private_key);
void atchops_rsa_key_private_key_set_e_initialized(atchops_rsa_key_private_key *private_key, const bool initialized);
int atchops_rsa_key_private_key_set_e(atchops_rsa_key_private_key *private_key, const unsigned char *e, const size_t e_len);
void atchops_rsa_key_private_key_unset_e(atchops_rsa_key_private_key *private_key);

bool atchops_rsa_key_private_key_is_d_initialized(atchops_rsa_key_private_key *private_key);
void atchops_rsa_key_private_key_set_d_initialized(atchops_rsa_key_private_key *private_key, const bool initialized);
int atchops_rsa_key_private_key_set_d(atchops_rsa_key_private_key *private_key, const unsigned char *d, const size_t d_len);
void atchops_rsa_key_private_key_unset_d(atchops_rsa_key_private_key *private_key);

bool atchops_rsa_key_private_key_is_p_initialized(atchops_rsa_key_private_key *private_key);
void atchops_rsa_key_private_key_set_p_initialized(atchops_rsa_key_private_key *private_key, const bool initialized);
int atchops_rsa_key_private_key_set_p(atchops_rsa_key_private_key *private_key, const unsigned char *p, const size_t p_len);
void atchops_rsa_key_private_key_unset_p(atchops_rsa_key_private_key *private_key);

bool atchops_rsa_key_private_key_is_q_initialized(atchops_rsa_key_private_key *private_key);
void atchops_rsa_key_private_key_set_q_initialized(atchops_rsa_key_private_key *private_key, const bool initialized);
int atchops_rsa_key_private_key_set_q(atchops_rsa_key_private_key *private_key, const unsigned char *q, const size_t q_len);
void atchops_rsa_key_private_key_unset_q(atchops_rsa_key_private_key *private_key);

#endif
