#pragma once

typedef struct rsakey_param
{
    unsigned long len;    // length of the number in bytes
    unsigned char *value; // hex byte array of the number
} rsakey_param;

typedef struct atchops_rsakey_publickey
{
    rsakey_param n; // modulus
    rsakey_param e; // public exponent
} atchops_rsakey_publickey;

typedef struct atchops_rsakey_privatekey
{
    rsakey_param n; // modulus
    rsakey_param e; // public exponent
    rsakey_param d; // private exponent
    rsakey_param p; // prime 1
    rsakey_param q; // prime 2
} atchops_rsakey_privatekey;

void atchops_rsakey_init_publickey(atchops_rsakey_publickey *publickey);
void atchops_rsakey_free_publickey(atchops_rsakey_publickey *publickey);

void atchops_rsakey_init_privatekey(atchops_rsakey_privatekey *privatekey);
void atchops_rsakey_free_privatekey(atchops_rsakey_privatekey *privatekey);

/**
 * @brief Populate a public key struct from a base64 string
 *
 * @param publickeystruct the public key struct to populate
 * @param publickeybase64 a base64 string representing an RSA 2048 Public Key
 * @param publickeybase64len the length of the base64 string
 * @return int 0 on success
 */
int atchops_rsakey_populate_publickey(atchops_rsakey_publickey *publickeystruct, const char *publickeybase64, const unsigned long publickeybase64len);

/**
 * @brief Populate a private key struct from a base64 string
 *
 * @param privatekeystruct the private key struct to populate
 * @param privatekeybase64 the base64 string representing an RSA 2048 Private Key
 * @param privatekeybase64len the length of the base64 string
 * @return int 0 on success
 */
int atchops_rsakey_populate_privatekey(atchops_rsakey_privatekey *privatekeystruct, const char *privatekeybase64, const unsigned long privatekeybase64len);
