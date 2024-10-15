#ifndef ATCLIENT_ATKEYS_H
#define ATCLIENT_ATKEYS_H

#include "atclient/atkeys_file.h"
#include <atchops/rsa.h>
#include <stddef.h>
#include <stdint.h>

#define VALUE_INITIALIZED 0b00000001

#define ATCLIENT_ATKEYS_PKAM_PUBLIC_KEY_INDEX 0
#define ATCLIENT_ATKEYS_PKAM_PRIVATE_KEY_INDEX 0
#define ATCLIENT_ATKEYS_ENCRYPT_PUBLIC_KEY_INDEX 0
#define ATCLIENT_ATKEYS_ENCRYPT_PRIVATE_KEY_INDEX 0
#define ATCLIENT_ATKEYS_SELF_ENCRYPTION_KEY_INDEX 0
#define ATCLIENT_ATKEYS_ENROLLMENT_ID_INDEX 0
#define ATCLIENT_ATKEYS_APKAM_SYMMETRIC_KEY_INDEX 0

#define ATCLIENT_ATKEYS_PKAM_PUBLIC_KEY_INITIALIZED (VALUE_INITIALIZED << 0)
#define ATCLIENT_ATKEYS_PKAM_PRIVATE_KEY_INITIALIZED (VALUE_INITIALIZED << 1)
#define ATCLIENT_ATKEYS_ENCRYPT_PUBLIC_KEY_INITIALIZED (VALUE_INITIALIZED << 2)
#define ATCLIENT_ATKEYS_ENCRYPT_PRIVATE_KEY_INITIALIZED (VALUE_INITIALIZED << 3)
#define ATCLIENT_ATKEYS_SELF_ENCRYPTION_KEY_INITIALIZED (VALUE_INITIALIZED << 4)
#define ATCLIENT_ATKEYS_ENROLLMENT_ID_INITIALIZED (VALUE_INITIALIZED << 5)
#define ATCLIENT_ATKEYS_APKAM_SYMMETRIC_KEY_INITIALIZED (VALUE_INITIALIZED << 6)

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
  char *pkam_public_key_base64;               // base64 encoded, RSA-2048 key, decrypted
  atchops_rsa_key_public_key pkam_public_key; // contains n, e

  char *pkam_private_key_base64;                // base64 encoded, RSA-2048 key, decrypted
  atchops_rsa_key_private_key pkam_private_key; // conatins n, e, d, p, q

  char *encrypt_public_key_base64;               // base64 encoded, RSA-2048 key, decrypted
  atchops_rsa_key_public_key encrypt_public_key; // contains n, e

  char *encrypt_private_key_base64;                // base64 encoded, RSA-2048 key, decrypted
  atchops_rsa_key_private_key encrypt_private_key; // conatins n, e, d, p, q

  char *self_encryption_key_base64; // base64 encoded, AES-256 key, decrypted

  char *apkam_symmetric_key_base64;
  char *enrollment_id;

  uint8_t _initialized_fields[1]; // used to track which fields have been initialized
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

int atclient_atkeys_set_pkam_public_key_base64(atclient_atkeys *atkeys, const char *pkam_public_key_base64,
                                               const size_t pkampublickeybase64len);

int atclient_atkeys_set_pkam_private_key_base64(atclient_atkeys *atkeys, const char *pkam_private_key_base64,
                                                const size_t pkamprivatekeybase64len);

int atclient_atkeys_set_encrypt_public_key_base64(atclient_atkeys *atkeys, const char *encrypt_public_key_base64,
                                                  const size_t encryptpublickeybase64len);

int atclient_atkeys_set_encrypt_private_key_base64(atclient_atkeys *atkeys, const char *encrypt_private_key_base64,
                                                   const size_t encryptprivatekeybase64len);

int atclient_atkeys_set_self_encryption_key_base64(atclient_atkeys *atkeys, const char *selfencryptionkeybase64,
                                                   const size_t selfencryptionkeybase64len);

int atclient_atkeys_set_apkam_symmetric_key_base64(atclient_atkeys *atkeys, const char *apkamsymmetrickeybase64,
                                                   const size_t apkamsymmetrickeybase64len);

int atclient_atkeys_set_enrollment_id(atclient_atkeys *atkeys, const char *enrollment_id,
                                      const size_t enrollment_id_len);

int atclient_atkeys_populate_pkam_public_key(atclient_atkeys *atkeys, const char *pkam_public_key_base64,
                                             const size_t pkampublickeybase64len);

int atclient_atkeys_populate_pkam_private_key(atclient_atkeys *atkeys, const char *pkam_private_key_base64,
                                              const size_t pkamprivatekeybase64len);

int atclient_atkeys_populate_encrypt_public_key(atclient_atkeys *atkeys, const char *encrypt_public_key_base64,
                                                const size_t encryptpublickeybase64len);

int atclient_atkeys_populate_encrypt_private_key(atclient_atkeys *atkeys, const char *encrypt_private_key_base64,
                                                 const size_t encryptprivatekeybase64len);

bool atclient_atkeys_is_pkam_public_key_base64_initialized(atclient_atkeys *atkeys);
bool atclient_atkeys_is_pkam_private_key_base64_initialized(atclient_atkeys *atkeys);
bool atclient_atkeys_is_encrypt_public_key_base64_initialized(atclient_atkeys *atkeys);
bool atclient_atkeys_is_encrypt_private_key_base64_initialized(atclient_atkeys *atkeys);
bool atclient_atkeys_is_self_encryption_key_base64_initialized(atclient_atkeys *atkeys);
bool atclient_atkeys_is_apkam_symmetric_key_base64_initialized(atclient_atkeys *atkeys);
bool atclient_atkeys_is_enrollment_id_initialized(atclient_atkeys *atkeys);

/**
 * @brief populates the struct by decrypting the encrypted RSA keys passed. It is assumed that the passed strings are
 * encrypted RSA keys that were in base64 format.
 *
 * @param atkeys the struct to populate, assumed to be intialized with atclient_atkeys_init
 * @param aes_pkam_public_key_str the encrypted RSA public key (encrypted with AES-256 selfencryptionkey) in base64
 * format
 * @param aes_pkam_public_key_len the length of the aes_pkam_public_key_str buffer
 * @param aes_pkam_private_key_str the encrypted RSA private key (encrypted with AES-256 selfencryptionkey) in base64
 * format
 * @param aes_pkam_private_key_len the length of the aes_pkam_private_key_str buffer
 * @param aes_encrypt_public_key_str  the encrypted RSA public key (encrypted with AES-256 selfencryptionkey) in base64
 * format
 * @param aes_encrypt_public_key_len the length of the aes_encrypt_public_key_str buffer
 * @param aes_encrypt_private_key_str the encrypted RSA private key (encrypted with AES-256 selfencryptionkey) in base64
 * format
 * @param aes_encrypt_private_key_len the length of the aes_encrypt_private_key_str buffer
 * @param self_encryption_key_str the (decrypted) AES-256 selfencryptionkey in base64 format
 * @param self_encryption_key_len the length of the self_encryption_key_str buffer
 * @param apkam_symmetric_key_str the (decrypted) AES-256 apkamsymmetrickey in base64 format, if this is an apkam key
 * @param apkam_symmetric_key_str_len the length of the apkam_symmetric_key_str buffer, if this is an apkam key
 * @param enrollment_id_str the enrollment id, if this is an apkam key
 * @param enrollment_id_str_length the length of enrollment_id_str, if this is an apkam key
 * @return int 0 on success, non-zero on failure
 */
int atclient_atkeys_populate_from_strings(atclient_atkeys *atkeys, const char *aes_pkam_public_key_str,
                                          const size_t aes_pkam_public_key_len, const char *aes_pkam_private_key_str,
                                          const size_t aes_pkam_private_key_len, const char *aes_encrypt_public_key_str,
                                          const size_t aes_encrypt_public_key_len,
                                          const char *aes_encrypt_private_key_str,
                                          const size_t aes_encrypt_private_key_len, const char *self_encryption_key_str,
                                          const size_t self_encryption_key_str_len, const char *apkam_symmetric_key_str,
                                          const size_t apkam_symmetric_key_str_len, const char *enrollment_id_str,
                                          const size_t enrollment_id_str_len);

/**
 * @brief populates the struct by decrypting the encrypted RSA keys found in a populated atclient_atkeys_file struct
 *
 * @param atkeys The struct to populate, assumed to be NON-NULL and initialized with atclient_atkeys_init
 * @param atkeys_file the struct containing the encrypted RSA keys, typically already read from the *.atKeys file
 * @return int 0 on success, non-zero on failure
 */
int atclient_atkeys_populate_from_atkeys_file(atclient_atkeys *atkeys, const atclient_atkeys_file *atkeys_file);

/**
 * @brief populates the atkeys struct by reading the *.atKeys file,
 * decrypting the RSA keys found in it, and populating the struct with the
 * decrypted keys
 *
 * @param atkeys The struct to populate, assumed to be NON-NULL and initialized with atclient_atkeys_init
 * @param path the path to the *.atKeys file
 * @return int 0 on success, non-zero on failure
 */
int atclient_atkeys_populate_from_path(atclient_atkeys *atkeys, const char *path);

/**
 * @brief Populates the atkeys struct by providing the string that you would have read from the atkeys file. This file
 * is useful in case your atKeys are in memory, which is common in embedded devices.
 *
 * @param atkeys The struct to populate, assumed to be NON-NULL and initialized with atclient_atkeys_init
 * @param file_string the string that would have been read from `_key.atKeys` file
 * @return int 0 on success
 */
int atclient_atkeys_populate_from_string(atclient_atkeys *atkeys, const char *file_string);

int atclient_atkeys_write_to_atkeys_file(atclient_atkeys *atkeys, atclient_atkeys_file *atkeys_file);

int atclient_atkeys_write_to_path(atclient_atkeys *atkeys, const char *path);

#endif
