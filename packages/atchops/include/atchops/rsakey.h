#ifndef ATCHOPS_RSAKEY_H
#define ATCHOPS_RSAKEY_H

#include <stdbool.h>
#include <stddef.h>

typedef struct atchops_rsakey_param {
  size_t len;                    // length of the number in bytes
  unsigned char *value;           // hex byte array of the number
  bool _is_value_initialized : 1; // whether the value is allocated
} atchops_rsakey_param;

typedef struct atchops_rsakey_publickey {
  atchops_rsakey_param n; // modulus
  atchops_rsakey_param e; // public exponent
} atchops_rsakey_publickey;

typedef struct atchops_rsakey_privatekey {
  atchops_rsakey_param n; // modulus
  atchops_rsakey_param e; // public exponent
  atchops_rsakey_param d; // private exponent
  atchops_rsakey_param p; // prime 1
  atchops_rsakey_param q; // prime 2
} atchops_rsakey_privatekey;

void atchops_rsakey_publickey_init(atchops_rsakey_publickey *publickey);
void atchops_rsakey_publickey_free(atchops_rsakey_publickey *publickey);

void atchops_rsakey_privatekey_init(atchops_rsakey_privatekey *privatekey);
void atchops_rsakey_privatekey_free(atchops_rsakey_privatekey *privatekey);

/**
 * @brief Deep clone an atchops_rsakey_publickey
 *
 * @param src the src from which to copy from
 * @param dst the new copy of key
 */
int atchops_rsakey_publickey_clone(const atchops_rsakey_publickey *src, atchops_rsakey_publickey *dst);

/**
 * @brief Deep clone an atchops_rsakey_privatekey
 *
 * @param src the src from which to copy from
 * @param dst the new copy of key
 */
int atchops_rsakey_privatekey_clone(const atchops_rsakey_privatekey *src, atchops_rsakey_privatekey *dst);

/**
 * @brief Populate a public key struct from a base64 string
 *
 * @param publickeystruct the public key struct to populate
 * @param publickeybase64 a base64 string representing an RSA 2048 Public Key
 * @param publickeybase64len the length of the base64 string
 * @return int 0 on success
 */
int atchops_rsakey_populate_publickey(atchops_rsakey_publickey *publickeystruct, const char *publickeybase64,
                                      const size_t publickeybase64len);

/**
 * @brief Populate a private key struct from a base64 string
 *
 * @param privatekeystruct the private key struct to populate
 * @param privatekeybase64 the base64 string representing an RSA 2048 Private Key
 * @param privatekeybase64len the length of the base64 string
 * @return int 0 on success
 */
int atchops_rsakey_populate_privatekey(atchops_rsakey_privatekey *privatekeystruct, const char *privatekeybase64,
                                       const size_t privatekeybase64len);

int atchops_rsakey_publickey_set_ne(atchops_rsakey_publickey *publickey, const unsigned char *n, const size_t nlen,
                                    const unsigned char *e, const size_t elen);

bool atchops_rsakey_publickey_is_n_initialized(atchops_rsakey_publickey *publickey);
int atchops_rsakey_publickey_set_n(atchops_rsakey_publickey *publickey, const unsigned char *n, const size_t nlen);
void atchops_rsakey_publickey_unset_n(atchops_rsakey_publickey *publickey);

bool atchops_rsakey_publickey_is_e_initialized(atchops_rsakey_publickey *publickey);
int atchops_rsakey_publickey_set_e(atchops_rsakey_publickey *publickey, const unsigned char *e, const size_t elen);
void atchops_rsakey_publickey_unset_e(atchops_rsakey_publickey *publickey);

int atchops_rsakey_privatekey_set_nedpq(atchops_rsakey_privatekey *privatekey, const unsigned char *n,
                                        const size_t nlen, const unsigned char *e, const size_t elen,
                                        const unsigned char *d, const size_t dlen, const unsigned char *p,
                                        const size_t plen, const unsigned char *q, const size_t qlen);

bool atchops_rsakey_privatekey_is_n_initialized(atchops_rsakey_privatekey *privatekey);
int atchops_rsakey_privatekey_set_n(atchops_rsakey_privatekey *privatekey, const unsigned char *n, const size_t nlen);
void atchops_rsakey_privatekey_unset_n(atchops_rsakey_privatekey *privatekey);

bool atchops_rsakey_privatekey_is_e_initialized(atchops_rsakey_privatekey *privatekey);
int atchops_rsakey_privatekey_set_e(atchops_rsakey_privatekey *privatekey, const unsigned char *e, const size_t elen);
void atchops_rsakey_privatekey_unset_e(atchops_rsakey_privatekey *privatekey);

bool atchops_rsakey_privatekey_is_d_initialized(atchops_rsakey_privatekey *privatekey);
int atchops_rsakey_privatekey_set_d(atchops_rsakey_privatekey *privatekey, const unsigned char *d, const size_t dlen);
void atchops_rsakey_privatekey_unset_d(atchops_rsakey_privatekey *privatekey);

bool atchops_rsakey_privatekey_is_p_initialized(atchops_rsakey_privatekey *privatekey);
int atchops_rsakey_privatekey_set_p(atchops_rsakey_privatekey *privatekey, const unsigned char *p, const size_t plen);
void atchops_rsakey_privatekey_unset_p(atchops_rsakey_privatekey *privatekey);

bool atchops_rsakey_privatekey_is_q_initialized(atchops_rsakey_privatekey *privatekey);
int atchops_rsakey_privatekey_set_q(atchops_rsakey_privatekey *privatekey, const unsigned char *q, const size_t qlen);
void atchops_rsakey_privatekey_unset_q(atchops_rsakey_privatekey *privatekey);

#endif
