#ifndef ATCLIENT_ATKEYS_H
#define ATCLIENT_ATKEYS_H

#include "atclient/atkeysfile.h"
#include "atclient/atstr.h"
#include <atchops/rsa.h>

/**
 * @brief represents the atkeys file
 * contains 5 keys: pkam public/private keypair, encrypt public/private keypair, and the aes-256 self encryption key.
 * each key contains
 * 1. the length of the buffer,
 * 2. the string that holds the decrypted base64 representation of the key with buffer length specified previously in
 * (1.)
 * 3. the evaluated length of the key (after population), you can imagine this as the *true* length of the key as
 * opposed to the buffer size used during memory allocation,
 * 4. (for rsakeys), the rsakey struct used in rsa operations.
 */
typedef struct atclient_atkeys {
  atclient_atstr pkampublickeystr;        // base64 encoded, RSA-2048 key, decrypted
  atchops_rsakey_publickey pkampublickey; // contains n, e

  atclient_atstr pkamprivatekeystr;         // base64 encoded, RSA-2048 key, decrypted
  atchops_rsakey_privatekey pkamprivatekey; // conatins n, e, d, p, q

  atclient_atstr encryptpublickeystr;        // base64 encoded, RSA-2048 key, decrypted
  atchops_rsakey_publickey encryptpublickey; // contains n, e

  atclient_atstr encryptprivatekeystr;         // base64 encoded, RSA-2048 key, decrypted
  atchops_rsakey_privatekey encryptprivatekey; // conatins n, e, d, p, q

  atclient_atstr selfencryptionkeystr; // base64 encoded, AES-256 key, decrypted
} atclient_atkeys;

/**
 * @brief initialize an atkeys struct
 *
 * @param atkeys a pointer to the struct to initialize
 */
void atclient_atkeys_init(atclient_atkeys *atkeys);

/**
 * @brief populates the struct by decrypting the encrypted RSA keys passed. It is assumed that the passed strings are
 * encrypted RSA keys that were in base64 format.
 *
 * @param atkeys the struct to populate
 * @param aespkampublickeystr the encrypted RSA public key (encrypted with AES-256 selfencryptionkey) in base64 format
 * @param aespkamprivatekeystr the encrypted RSA private key (encrypted with AES-256 selfencryptionkey) in base64 format
 * @param aesencryptpublickeystr  the encrypted RSA public key (encrypted with AES-256 selfencryptionkey) in base64
 * format
 * @param aesencryptprivatekeystr the encrypted RSA private key (encrypted with AES-256 selfencryptionkey) in base64
 * format
 * @param selfencryptionkeystr the (decrypted) AES-256 selfencryptionkey in base64 format
 * @return int 0 on success, non-zero on failure
 */
int atclient_atkeys_populate_from_strings(atclient_atkeys *atkeys, const char *aespkampublickeystr,
                                          const unsigned long aespkampublickeylen, const char *aespkamprivatekeystr,
                                          const unsigned long aespkamprivatekeylen, const char *aesencryptpublickeystr,
                                          const unsigned long aesencryptpublickeylen,
                                          const char *aesencryptprivatekeystr,
                                          const unsigned long aesencryptprivatekeylen, const char *selfencryptionkeystr,
                                          const unsigned long selfencryptionkeylen);

/**
 * @brief populates the struct by decrypting the encrypted RSA keys found in a populated atclient_atkeysfile struct
 *
 * @param atkeys the struct to populate
 * @param atkeysfile the struct containing the encrypted RSA keys, typically already read from the *.atKeys file
 * @return int 0 on success, non-zero on failure
 */
int atclient_atkeys_populate_from_atkeysfile(atclient_atkeys *atkeys, atclient_atkeysfile atkeysfile);

/**
 * @brief populates the atkeys struct by reading the *.atKeys file,
 * decrypting the RSA keys found in it, and populating the struct with the
 * decrypted keys
 *
 * @param atkeys the struct to populate
 * @param path the path to the *.atKeys file
 * @return int
 */
int atclient_atkeys_populate_from_path(atclient_atkeys *atkeys, const char *path);

/**
 * @brief free memory allocated by the init function
 *
 * @param atkeys the atkeys struct to free
 */
void atclient_atkeys_free(atclient_atkeys *atkeys);

#endif
