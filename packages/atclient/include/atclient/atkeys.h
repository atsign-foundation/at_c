
#pragma once

#include "atclient/atkeysfile.h"
#include "atchops/rsa.h"

typedef struct atclient_atkeys
{
    unsigned long pkampublickeylen;
    unsigned char *pkampublickeystr; // base64 encoded, decrypted
    unsigned long pkampublickeyolen;
    atchops_rsa_publickey pkampublickey; // contains n, e

    unsigned long pkamprivatekeylen;
    unsigned char *pkamprivatekeystr; // base64 encoded, decrypted
    unsigned long pkamprivatekeyolen;
    atchops_rsa_privatekey pkam_private_key; // conatins n, e, d, p, q

    unsigned long encryptpublickeylen;
    unsigned char *encryptpublickeystr; // base64 encoded, decrypted
    unsigned long encryptpublickeyolen;
    atchops_rsa_publickey encryptpublickey; // contains n, e

    unsigned long encryptprivatekeylen;
    unsigned char *encryptprivatekeystr; // base64 encoded, decrypted
    unsigned long encryptprivatekeyolen;
    atchops_rsa_privatekey encryptprivatekey; // conatins n, e, d, p, q

    unsigned long selfencryptionkeylen;
    unsigned char *selfencryptionkeystr; // base64 encoded, decrypted
    unsigned long selfencryptionkeyolen;
} atclient_atkeys;

void atclient_atkeys_init(atclient_atkeys *atkeys);

/**
 * @brief populates the struct by decrypting the encrypted RSA keys found in a populated atclient_atkeysfile struct
 *
 * @param atkeys the struct to populate
 * @param atkeysfile the struct containing the encrypted RSA keys, typically already read from the *.atKeys file
 * @return int
 */
int atclient_atkeys_populate(atclient_atkeys *atkeys, atclient_atkeysfile atkeysfile);
void atclient_atkeys_free(atclient_atkeys *atkeys);