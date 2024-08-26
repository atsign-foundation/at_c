#ifndef ATCLIENT_ATKEYSFILE_H
#define ATCLIENT_ATKEYSFILE_H

#include <stddef.h>
#include <stdint.h>

#define VALUE_INITIALIZED 0b00000001

#define ATCLIENT_ATKEYSFILE_AES_PKAM_PUBLIC_KEY_STR_INDEX 0
#define ATCLIENT_ATKEYSFILE_AES_PKAM_PRIVATE_KEY_STR_INDEX 0
#define ATCLIENT_ATKEYSFILE_AES_ENCRYPT_PUBLIC_KEY_STR_INDEX 0
#define ATCLIENT_ATKEYSFILE_AES_ENCRYPT_PRIVATE_KEY_STR_INDEX 0
#define ATCLIENT_ATKEYSFILE_SELF_ENCRYPTION_KEY_STR_INDEX 0

#define ATCLIENT_ATKEYSFILE_AES_PKAM_PUBLIC_KEY_STR_INITIALIZED (VALUE_INITIALIZED << 0)
#define ATCLIENT_ATKEYSFILE_AES_PKAM_PRIVATE_KEY_STR_INITIALIZED (VALUE_INITIALIZED << 1)
#define ATCLIENT_ATKEYSFILE_AES_ENCRYPT_PUBLIC_KEY_STR_INITIALIZED (VALUE_INITIALIZED << 2)
#define ATCLIENT_ATKEYSFILE_AES_ENCRYPT_PRIVATE_KEY_STR_INITIALIZED (VALUE_INITIALIZED << 3)
#define ATCLIENT_ATKEYSFILE_SELF_ENCRYPTION_KEY_STR_INITIALIZED (VALUE_INITIALIZED << 4)

typedef struct atclient_atkeysfile {
  char *aes_pkam_public_key_str; // encrypted with self encryption key. AES decryption with self encryption key will reveal base64-encoded RSA key
  char *aes_pkam_private_key_str; // encrypted with self encryption key. AES decryption with self encryption key will reveal base64-encoded RSA keyF
  char *aes_encrypt_public_key_str; // encrypted with self encryption key. AES decryption with self encryption key will reveal base64-encoded RSA key
  char *aes_encrypt_private_key_str; // encrypted with self encryption key. AES decryption with self encryption key will reveal base64-encoded RSA key
  char *self_encryption_key_str; // base64-encoded non-encrypted self encryption key. base64 decoding will reveal 32-byte AES key
  uint8_t _initialized_fields[1];
} atclient_atkeysfile;

void atclient_atkeysfile_init(atclient_atkeysfile *atkeysfile);
int atclient_atkeysfile_read(atclient_atkeysfile *atkeysfile, const char *path);
void atclient_atkeysfile_free(atclient_atkeysfile *atkeysfile);

#endif
