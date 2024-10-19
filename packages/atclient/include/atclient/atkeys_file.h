#ifndef ATCLIENT_ATKEYS_FILE_H
#define ATCLIENT_ATKEYS_FILE_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define VALUE_INITIALIZED 0b00000001

#define ATCLIENT_ATKEYS_FILE_AES_PKAM_PUBLIC_KEY_STR_INDEX 0
#define ATCLIENT_ATKEYS_FILE_AES_PKAM_PRIVATE_KEY_STR_INDEX 0
#define ATCLIENT_ATKEYS_FILE_AES_ENCRYPT_PUBLIC_KEY_STR_INDEX 0
#define ATCLIENT_ATKEYS_FILE_AES_ENCRYPT_PRIVATE_KEY_STR_INDEX 0
#define ATCLIENT_ATKEYS_FILE_SELF_ENCRYPTION_KEY_STR_INDEX 0
#define ATCLIENT_ATKEYS_FILE_APKAM_SYMMETRIC_KEY_STR_INDEX 0
#define ATCLIENT_ATKEYS_FILE_ENROLLMENT_ID_STR_INDEX 0
#define ATCLIENT_ATKEYS_FILE_APKAM_SYMMETRIC_KEY_STR_INDEX 0

#define ATCLIENT_ATKEYS_FILE_AES_PKAM_PUBLIC_KEY_STR_INITIALIZED (VALUE_INITIALIZED << 0)
#define ATCLIENT_ATKEYS_FILE_AES_PKAM_PRIVATE_KEY_STR_INITIALIZED (VALUE_INITIALIZED << 1)
#define ATCLIENT_ATKEYS_FILE_AES_ENCRYPT_PUBLIC_KEY_STR_INITIALIZED (VALUE_INITIALIZED << 2)
#define ATCLIENT_ATKEYS_FILE_AES_ENCRYPT_PRIVATE_KEY_STR_INITIALIZED (VALUE_INITIALIZED << 3)
#define ATCLIENT_ATKEYS_FILE_SELF_ENCRYPTION_KEY_STR_INITIALIZED (VALUE_INITIALIZED << 4)
#define ATCLIENT_ATKEYS_FILE_APKAM_SYMMETRIC_KEY_STR_INITIALIZED (VALUE_INITIALIZED << 5)
#define ATCLIENT_ATKEYS_FILE_ENROLLMENT_ID_STR_INITIALIZED (VALUE_INITIALIZED << 6)

#define ATCLIENT_ATKEYS_FILE_APKAM_PUBLIC_KEY_JSON_KEY "aesPkamPublicKey"
#define ATCLIENT_ATKEYS_FILE_APKAM_PRIVATE_KEY_JSON_KEY "aesPkamPrivateKey"
#define ATCLIENT_ATKEYS_FILE_DEFAULT_ENCRYPTION_PUBLIC_KEY_JSON_KEY "aesEncryptPublicKey"
#define ATCLIENT_ATKEYS_FILE_DEFAULT_ENCRYPTION_PRIVATE_KEY_JSON_KEY "aesEncryptPrivateKey"
#define ATCLIENT_ATKEYS_FILE_DEFAULT_SELF_ENCRYPTION_KEY_JSON_KEY "selfEncryptionKey"
#define ATCLIENT_ATKEYS_FILE_APKAM_SYMMETRIC_KEY_JSON_KEY "apkamSymmetricKey"
#define ATCLIENT_ATKEYS_FILE_APKAM_ENROLLMENT_ID_JSON_KEY "enrollmentId"

typedef struct atclient_atkeys_file {
  // note: `aes_` prefix means the field is encrypted with aes, not that the type of key is aes
  char *aes_pkam_public_key_str;     // encrypted with self encryption key. AES decryption with self encryption key will
                                     // reveal base64-encoded RSA key
  char *aes_pkam_private_key_str;    // encrypted with self encryption key. AES decryption with self encryption key will
                                     // reveal base64-encoded RSA keyF
  char *aes_encrypt_public_key_str;  // encrypted with self encryption key. AES decryption with self encryption key will
                                     // reveal base64-encoded RSA key
  char *aes_encrypt_private_key_str; // encrypted with self encryption key. AES decryption with self encryption key will
                                     // reveal base64-encoded RSA key
  char *self_encryption_key_str;     // base64-encoded non-encrypted self encryption key. base64 decoding will reveal
                                     // 32-byte AES key
  char *apkam_symmetric_key_str;
  char *enrollment_id_str;
  uint8_t _initialized_fields[1];
} atclient_atkeys_file;

/**
 * @brief Initialize the struct. This function does not allocate the struct, but manages its memory internally. This
 * function should be called before any subsequent calls.
 *
 * @param atkeys_file the allocated struct to be initialized.
 */
void atclient_atkeys_file_init(atclient_atkeys_file *atkeys_file);

/**
 * @brief Read from a `_key.atKeys` file path.
 *
 * @param atkeys_file the struct to be populated, assumed to be NON-NULL and initialized with atclient_atkeys_file_init
 * @param path  Example "$HOME/.atsign/keys/@alice_key.atKeys"
 * @return int
 */
int atclient_atkeys_file_from_path(atclient_atkeys_file *atkeys_file, const char *path);

/**
 * @brief Read from a string. You would typically read the file first and then call this function to populate your
 * *atkeys_file struct.
 *
 * @param atkeys_file the struct to be populated, assumed to be NON-NULL and initialized with atclient_atkeys_file_init
 * @param file_string the string that is read from the `_key.atKeys` file.
 * @return int
 */
int atclient_atkeys_file_from_string(atclient_atkeys_file *atkeys_file, const char *file_string);

/**
 * @brief Write the struct to a file.
 * 
 * @param atkeys_file the struct to be written to the file, assumed to be NON-NULL and initialized with atclient_atkeys_file_init
 * @param path  Example "$HOME/.atsign/keys/@alice_key.atKeys"
 */
int atclient_atkeys_file_write_to_path(atclient_atkeys_file *atkeys_file, const char *path);

/**
 * @brief Free the struct of any memory that was allocated during its lifetime
 *
 * @param atkeys_file the struct to be populated, assumed to be NON-NULL and initialized with atclient_atkeys_file_init
 */
void atclient_atkeys_file_free(atclient_atkeys_file *atkeys_file);

bool atclient_atkeys_file_is_aes_pkam_public_key_str_initialized(atclient_atkeys_file *atkeys_file);
bool atclient_atkeys_file_is_aes_pkam_private_key_str_initialized(atclient_atkeys_file *atkeys_file);
bool atclient_atkeys_file_is_aes_encrypt_public_key_str_initialized(atclient_atkeys_file *atkeys_file);
bool atclient_atkeys_file_is_aes_encrypt_private_key_str_initialized(atclient_atkeys_file *atkeys_file);
bool atclient_atkeys_file_is_self_encryption_key_str_initialized(atclient_atkeys_file *atkeys_file);
bool atclient_atkeys_file_is_apkam_symmetric_key_str_initialized(atclient_atkeys_file *atkeys_file);
bool atclient_atkeys_file_is_enrollment_id_str_initialized(atclient_atkeys_file *atkeys_file);

int atclient_atkeys_file_set_aes_pkam_public_key_str(atclient_atkeys_file *atkeys_file,
                                                     const char *aes_pkam_public_key_str,
                                                     const size_t aes_pkam_public_key_str_len);
int atclient_atkeys_file_set_aes_pkam_private_key_str(atclient_atkeys_file *atkeys_file,
                                                      const char *aes_pkam_private_key_str,
                                                      const size_t aes_pkam_private_key_str_len);
int atclient_atkeys_file_set_aes_encrypt_public_key_str(atclient_atkeys_file *atkeys_file,
                                                        const char *aes_encrypt_public_key_str,
                                                        const size_t aes_encrypt_public_key_str_len);
int atclient_atkeys_file_set_aes_encrypt_private_key_str(atclient_atkeys_file *atkeys_file,
                                                         const char *aes_encrypt_private_key_str,
                                                         const size_t aes_encrypt_private_key_str_len);
int atclient_atkeys_file_set_self_encryption_key_str(atclient_atkeys_file *atkeys_file,
                                                     const char *self_encryption_key_str,
                                                     const size_t self_encryption_key_str_len);
int atclient_atkeys_file_set_apkam_symmetric_key_str(atclient_atkeys_file *atkeys_file,
                                                     const char *apkam_symmetric_key_str,
                                                     const size_t apkam_symmetric_key_str_len);
int atclient_atkeys_file_set_enrollment_id_str(atclient_atkeys_file *atkeys_file, const char *enrollment_id_str,
                                               const size_t enrollment_id_str_len);

#endif
