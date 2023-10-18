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
    unsigned long len;
    char *key;
} atclient_atkeysfile_entry;

typedef struct atclient_atkeysfile {
    atclient_atkeysfile_entry *aes_pkam_public_key;
    atclient_atkeysfile_entry *aes_pkam_private_key;
    atclient_atkeysfile_entry *aes_encrypt_public_key;
    atclient_atkeysfile_entry *aes_encrypt_private_key;
    atclient_atkeysfile_entry *self_encryption_key;
} atclient_atkeysfile;

void atclient_atkeysfile_init(atclient_atkeysfile *atkeysfile);
int atclient_atkeysfile_read(const char *path, atclient_atkeysfile *atkeysfile);
int atclient_atkeysfile_write(const char *path, const char *atsign, atclient_atkeysfile *atkeysfile);
void atclient_atkeysfile_free(atclient_atkeysfile *atkeysfile);

/**
 * Usage example
 * atclient_atkeysfile atkeysfile;
 * atclient_atkeysfile_init(&atkeysfile);
 * printf("done init...\n")
 *
    ret = atclient_atkeysfile_read(path, &atkeysfile);
    if (ret != 0)
    {
        goto exit;
    }

    printf("done read...\n");
    printf("aes_pkam_public_key: %s\n", atkeysfile.aes_pkam_public_key->key);
    printf("aes_pkam_private_key: %s\n", atkeysfile.aes_pkam_private_key->key);
    printf("aes_encrypt_public_key: %s\n", atkeysfile.aes_encrypt_public_key->key);
    printf("aes_encrypt_private_key: %s\n", atkeysfile.aes_encrypt_private_key->key);
    printf("self_encryption_key: %s\n", atkeysfile.self_encryption_key->key);

    printf("writing...\n");

    ret = atclient_atkeysfile_write("/Users/jeremytubongbanua/.atsign/temp/@smoothalligator_key.atKeys", ATSIGN, &atkeysfile);
 *
 */