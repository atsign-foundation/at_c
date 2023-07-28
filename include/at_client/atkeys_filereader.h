#pragma once

#define TOKEN_AES_PKAM_PUBLIC_KEY "aesPkamPublicKey"
#define TOKEN_AES_PKAM_PUBLIC_KEY_LEN 16

#define TOKEN_AES_PKAM_PRIVATE_KEY "aesPkamPrivateKey"
#define TOKEN_AES_PKAM_PRIVATE_KEY_LEN 17

#define TOKEN_AES_ENCRYPT_PUBLIC_KEY "aesEncryptPublicKey"
#define TOKEN_AES_ENCRYPT_PUBLIC_KEY_LEN 19

#define TOKEN_AES_ENCRYPT_PRIVATE_KEY "aesEncryptPrivateKey"
#define TOKEN_AES_ENCRYPT_PRIVATE_KEY_LEN 20

#define TOKEN_SELF_ENCRYPTION_KEY "selfEncryptionKey"
#define TOKEN_SELF_ENCRYPTION_KEY_LEN 17

typedef struct atclient_atkeysfile_entry{
    size_t len;
    char *key;
} atclient_atkeysfile_entry;

typedef struct atclient_atkeysfile {
    atclient_atkeysfile_entry *aes_pkam_public_key;
    atclient_atkeysfile_entry *aes_pkam_private_key;
    atclient_atkeysfile_entry *aes_encrypt_public_key;
    atclient_atkeysfile_entry *aes_encrypt_private_key;
    atclient_atkeysfile_entry *self_encryption_key;
    atclient_atkeysfile_entry *atsign;
} atclient_atkeysfile;

void atclient_atkeysfile_init(atclient_atkeysfile* atkeysfile);
int atclient_atkeysfile_read(const char *path, const size_t pathlen, atclient_atkeysfile *atsign);
int atclient_atkeysfile_write(const char *path, const size_t pathlen, atclient_atkeysfile *atsign);
void atclient_atkeysfile_free(atclient_atkeysfile* atkeysfile);