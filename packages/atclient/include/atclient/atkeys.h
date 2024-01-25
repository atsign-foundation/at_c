#ifndef ATCLIENT_ATKEYS_H
#define ATCLIENT_ATKEYS_H

#include <atchops/rsa.h>
#include "atclient/atkeysfile.h"

/**
 * @brief represents the atkeys file
 * 
 * contains 5 keys: pkam public/private keypair, encrypt public/private keypair, and the aes-256 self encryption key.
 * each key contains 
 * 1. the length of the buffer, 
 * 2. the string that holds the decrypted base64 representation of the key with buffer length specified previously in (1.)
 * 3. the evaluated length of the key (after population), you can imagine this as the *true* length of the key as opposed to the buffer size used during memory allocation,
 * 4. (for rsakeys), the rsakey struct used in rsa operations.
 * 
 */
typedef struct atclient_atkeys
{
    unsigned long pkampublickeylen;
    char *pkampublickeystr; // base64 encoded, decrypted
    unsigned long pkampublickeyolen;
    atchops_rsakey_publickey pkampublickey; // contains n, e

    unsigned long pkamprivatekeylen;
    char *pkamprivatekeystr; // base64 encoded, decrypted
    unsigned long pkamprivatekeyolen;
    atchops_rsakey_privatekey pkamprivatekey; // conatins n, e, d, p, q

    unsigned long encryptpublickeylen;
    char *encryptpublickeystr; // base64 encoded, decrypted
    unsigned long encryptpublickeyolen;
    atchops_rsakey_publickey encryptpublickey; // contains n, e

    unsigned long encryptprivatekeylen;
    char *encryptprivatekeystr; // base64 encoded, decrypted
    unsigned long encryptprivatekeyolen;
    atchops_rsakey_privatekey encryptprivatekey; // conatins n, e, d, p, q

    unsigned long selfencryptionkeylen;
    char *selfencryptionkeystr; // base64 encoded, decrypted
    unsigned long selfencryptionkeyolen;
} atclient_atkeys;

/**
 * @brief initialize an atkeys struct
 * 
 * @param atkeys a pointer to the struct to initialize
 */
void atclient_atkeys_init(atclient_atkeys *atkeys);

/**
 * @brief populates the struct by decrypting the encrypted RSA keys found in a populated atclient_atkeysfile struct
 *
 * @param atkeys the struct to populate
 * @param atkeysfile the struct containing the encrypted RSA keys, typically already read from the *.atKeys file
 * @return int
 */
int atclient_atkeys_populate(atclient_atkeys *atkeys, atclient_atkeysfile atkeysfile);

/**
 * @brief free memory allocated by the init function
 * 
 * @param atkeys the atkeys struct to free
 */
void atclient_atkeys_free(atclient_atkeys *atkeys);

#endif