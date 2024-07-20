#ifndef ATCLIENT_ATKEYS_H
#define ATCLIENT_ATKEYS_H

#include "atclient/atkeysfile.h"
#include "atclient/atstr.h"
#include <atchops/rsa.h>
#include <stddef.h>
#include <stdint.h>

#define VALUE_INITIALIZED 0b00000001

#define PKAMPUBLICKEY_INDEX 0
#define PKAMPRIVATEKEY_INDEX 0
#define ENCRYPTPUBLICKEY_INDEX 0
#define ENCRYPTPRIVATEKEY_INDEX 0
#define SELFENCRYPTIONKEY_INDEX 0

#define PKAMPUBLICKEY_INITIALIZED (VALUE_INITIALIZED << 0)
#define PKAMPRIVATEKEY_INITIALIZED (VALUE_INITIALIZED << 1)
#define ENCRYPTPUBLICKEY_INITIALIZED (VALUE_INITIALIZED << 2)
#define ENCRYPTPRIVATEKEY_INITIALIZED (VALUE_INITIALIZED << 3)
#define SELFENCRYPTIONKEY_INITIALIZED (VALUE_INITIALIZED << 4)

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
  char *pkampublickeybase64;              // base64 encoded, RSA-2048 key, decrypted
  atchops_rsakey_publickey pkampublickey; // contains n, e

  char *pkamprivatekeybase64;               // base64 encoded, RSA-2048 key, decrypted
  atchops_rsakey_privatekey pkamprivatekey; // conatins n, e, d, p, q

  char *encryptpublickeybase64;              // base64 encoded, RSA-2048 key, decrypted
  atchops_rsakey_publickey encryptpublickey; // contains n, e

  char *encryptprivatekeybase64;               // base64 encoded, RSA-2048 key, decrypted
  atchops_rsakey_privatekey encryptprivatekey; // conatins n, e, d, p, q

  char *selfencryptionkeybase64; // base64 encoded, AES-256 key, decrypted

  uint8_t _initializedfields[1]; // used to track which fields have been initialized
} atclient_atkeys;

/**
 * @brief initialize an atkeys struct
 *
 * @param atkeys a pointer to the struct to initialize
 */
void atclient_atkeys_init(atclient_atkeys *atkeys);

/**
 * @brief free memory allocated by the init function
 *
 * @param atkeys the atkeys struct to free
 */
void atclient_atkeys_free(atclient_atkeys *atkeys);

/**
 * @brief populates the struct by decrypting the encrypted RSA keys passed. It is assumed that the passed strings are
 * encrypted RSA keys that were in base64 format.
 *
 * @param atkeys the struct to populate, assumed to be intialized with atclient_atkeys_init
 * @param aespkampublickeystr the encrypted RSA public key (encrypted with AES-256 selfencryptionkey) in base64 format
 * @param aespkampublickeylen the length of the aespkampublickeystr buffer
 * @param aespkamprivatekeystr the encrypted RSA private key (encrypted with AES-256 selfencryptionkey) in base64 format
 * @param aespkamprivatekeylen the length of the aespkamprivatekeystr buffer
 * @param aesencryptpublickeystr  the encrypted RSA public key (encrypted with AES-256 selfencryptionkey) in base64
 * format
 * @param aesencryptpublickeylen the length of the aesencryptpublickeystr buffer
 * @param aesencryptprivatekeystr the encrypted RSA private key (encrypted with AES-256 selfencryptionkey) in base64
 * format
 * @param aesencryptprivatekeylen the length of the aesencryptprivatekeystr buffer
 * @param selfencryptionkeystr the (decrypted) AES-256 selfencryptionkey in base64 format
 * @param selfencryptionkeylen the length of the selfencryptionkeystr buffer
 * @return int 0 on success, non-zero on failure
 */
int atclient_atkeys_populate_from_strings(atclient_atkeys *atkeys, const char *aespkampublickeystr,
                                          const size_t aespkampublickeylen, const char *aespkamprivatekeystr,
                                          const size_t aespkamprivatekeylen, const char *aesencryptpublickeystr,
                                          const size_t aesencryptpublickeylen, const char *aesencryptprivatekeystr,
                                          const size_t aesencryptprivatekeylen, const char *selfencryptionkeystr,
                                          const size_t selfencryptionkeylen);

/**
 * @brief populates the struct by decrypting the encrypted RSA keys found in a populated atclient_atkeysfile struct
 *
 * @param atkeys the struct to populate
 * @param atkeysfile the struct containing the encrypted RSA keys, typically already read from the *.atKeys file
 * @return int 0 on success, non-zero on failure
 */
int atclient_atkeys_populate_from_atkeysfile(atclient_atkeys *atkeys, const atclient_atkeysfile atkeysfile);

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

#endif
