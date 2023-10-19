
#pragma once

#include "atclient/atkeysfile.h"
#include "atchops/rsa.h"

typedef struct atclient_atkeys {
    unsigned long pkam_public_key_len;
    unsigned char pkam_public_key_str; // base64 encoded, decrypted
    unsigned long pkam_public_key_olen;
    atchops_rsa_publickey pkam_public_key; // contains n, e

    unsigned long pkam_private_key_len;
    unsigned char pkam_private_key_str; // base64 encoded, decrypted
    unsigned long pkam_private_key_olen;
    atchops_rsa_privatekey pkam_private_key; // conatins n, e, d, p, q

    unsigned long encrypt_public_key_len;
    unsigned char encrypt_public_key_str; // base64 encoded, decrypted
    unsigned long encrypt_public_key_olen;
    atchops_rsa_publickey encrypt_public_key; // contains n, e
    
    unsigned long encrypt_private_key_len;
    unsigned char encrypt_private_key_str; // base64 encoded, decrypted
    unsigned long encrypt_private_key_olen;
    atchops_rsa_privatekey encrypt_private_key; // conatins n, e, d, p, q

    unsigned long self_encryption_key_len;
    unsigned char self_encryption_key; // base64 encoded, decrypted
    unsigned long self_encryption_key_olen;
} atclient_atkeys;

void atclient_atkeys_init(atclient_atkeys *atkeys);

/**
 * @brief populates the struct by decrypting the encrypted RSA keys found in a populated atclient_atkeysfile struct
 * 
 * @param atkeys the struct to populate
 * @param atkeysfile the struct containing the encrypted RSA keys, typically already read from the *.atKeys file
 * @return int 
 */
int atclient_atkeys_populate(atclient_atkeys *atkeys, atclient_atkeysfile *atkeysfile);
void atclient_atkeys_free(atclient_atkeys *atkeys);