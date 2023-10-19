#pragma once

typedef struct atclient_atkeysfile {
    unsigned long aes_pkam_public_key_len;
    unsigned char *aes_pkam_public_key;
    unsigned long aes_pkam_public_key_olen;

    unsigned long aes_pkam_private_key_len;
    unsigned char *aes_pkam_private_key;
    unsigned long aes_pkam_private_key_olen;

    unsigned long aes_encrypt_public_key_len;
    unsigned char *aes_encrypt_public_key;
    unsigned long aes_encrypt_public_key_olen;

    unsigned long aes_encrypt_private_key_len;
    unsigned char *aes_encrypt_private_key;
    unsigned long aes_encrypt_private_key_olen;

    unsigned long self_encryption_key_len;
    unsigned char *self_encryption_key;
    unsigned long self_encryption_key_olen;
} atclient_atkeysfile;

void atclient_atkeysfile_init(atclient_atkeysfile *atkeysfile);
int atclient_atkeysfile_read(atclient_atkeysfile *atkeysfile, const char *path);
int atclient_atkeysfile_write(atclient_atkeysfile *atkeysfile, const char *path, const char *atsign);
void atclient_atkeysfile_free(atclient_atkeysfile *atkeysfile);
