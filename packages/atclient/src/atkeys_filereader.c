#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "atclient/atkeys_filereader.h"

#define KEY_CHAR_PRIVATE_MAX_LEN 4000 // base64 encoded private key at most 4000 char len
#define KEY_CHAR_PUBLIC_MAX_LEN 1000  // base64 encoded public key at most 1000 char len
#define KEY_CHAR_AES256_MAX_LEN 100   // baes64 encoded aes256 key at most 100 char len
#define KEY_CHAR_ATSIGN_MAX_LEN 100   // atsign at most 100 char len, e.g. @alice

void atclient_atkeysfile_init(atclient_atkeysfile *atkeysfile)
{
    atkeysfile->aes_encrypt_private_key = malloc(sizeof(atclient_atkeysfile_entry));
    atkeysfile->aes_encrypt_private_key->len = KEY_CHAR_PRIVATE_MAX_LEN;
    atkeysfile->aes_encrypt_private_key->key = malloc(sizeof(char) * atkeysfile->aes_encrypt_private_key->len);
    memset(atkeysfile->aes_encrypt_private_key->key, 0, atkeysfile->aes_encrypt_private_key->len);

    atkeysfile->aes_encrypt_public_key = malloc(sizeof(atclient_atkeysfile_entry));
    atkeysfile->aes_encrypt_public_key->len = KEY_CHAR_PUBLIC_MAX_LEN;
    atkeysfile->aes_encrypt_public_key->key = malloc(sizeof(char) * atkeysfile->aes_encrypt_public_key->len);
    memset(atkeysfile->aes_encrypt_public_key->key, 0, atkeysfile->aes_encrypt_public_key->len);

    atkeysfile->aes_pkam_private_key = malloc(sizeof(atclient_atkeysfile_entry));
    atkeysfile->aes_pkam_private_key->len = KEY_CHAR_PRIVATE_MAX_LEN;
    atkeysfile->aes_pkam_private_key->key = malloc(sizeof(char) * atkeysfile->aes_pkam_private_key->len);
    memset(atkeysfile->aes_pkam_private_key->key, 0, atkeysfile->aes_pkam_private_key->len);

    atkeysfile->aes_pkam_public_key = malloc(sizeof(atclient_atkeysfile_entry));
    atkeysfile->aes_pkam_public_key->len = KEY_CHAR_PUBLIC_MAX_LEN;
    atkeysfile->aes_pkam_public_key->key = malloc(sizeof(char) * atkeysfile->aes_pkam_public_key->len);
    memset(atkeysfile->aes_pkam_public_key->key, 0, atkeysfile->aes_pkam_public_key->len);

    atkeysfile->self_encryption_key = malloc(sizeof(atclient_atkeysfile_entry));
    atkeysfile->self_encryption_key->len = KEY_CHAR_AES256_MAX_LEN;
    atkeysfile->self_encryption_key->key = malloc(sizeof(char) * atkeysfile->self_encryption_key->len);
    memset(atkeysfile->self_encryption_key->key, 0, atkeysfile->self_encryption_key->len);
}

enum currently_viewing
{
    NONE = 0,
    AES_PKAM_PUBLIC_KEY,
    AES_PKAM_PRIVATE_KEY,
    AES_ENCRYPT_PUBLIC_KEY,
    AES_ENCRYPT_PRIVATE_KEY,
    SELF_ENCRYPTION_KEY
};

int atclient_atkeysfile_read(const char *path, atclient_atkeysfile *atkeysfile)
{
    int ret = 1;

    FILE *file = fopen(path, "r");
    if (file == NULL)
    {
        printf("Error opening file!\n");
        ret = 1;
        goto exit;
    }

    char c;
    short i = 0;

    short word_max_len = 50;
    char *word = malloc(sizeof(char) * word_max_len);
    memset(word, 0, word_max_len);

    enum currently_viewing curr = NONE;
    while ((c = fgetc(file)) != EOF)
    {
        if (c == '}' || c == '{' || c == ':')
        {
            continue;
        }
        else if (c == '"')
        {
            memset(word, 0, word_max_len);
            i = 0;
            continue;
        }
        else if (c == ',')
        {
            curr = NONE;
            continue;
        }
        switch (curr)
        {
        case NONE:
        {
            *(word + i++) = c;
            if (strncmp(word, TOKEN_AES_PKAM_PUBLIC_KEY, TOKEN_AES_PKAM_PUBLIC_KEY_LEN) == 0)
            {
                curr = AES_PKAM_PUBLIC_KEY;
                memset(word, 0, word_max_len);
                i = 0;
            }
            else if (strncmp(word, TOKEN_AES_PKAM_PRIVATE_KEY, TOKEN_AES_PKAM_PRIVATE_KEY_LEN) == 0)
            {
                curr = AES_PKAM_PRIVATE_KEY;
                memset(word, 0, word_max_len);
                i = 0;
            }
            else if (strncmp(word, TOKEN_AES_ENCRYPT_PUBLIC_KEY, TOKEN_AES_ENCRYPT_PUBLIC_KEY_LEN) == 0)
            {
                curr = AES_ENCRYPT_PUBLIC_KEY;
                memset(word, 0, word_max_len);
                i = 0;
            }
            else if (strncmp(word, TOKEN_AES_ENCRYPT_PRIVATE_KEY, TOKEN_AES_ENCRYPT_PRIVATE_KEY_LEN) == 0)
            {
                curr = AES_ENCRYPT_PRIVATE_KEY;
                memset(word, 0, word_max_len);
                i = 0;
            }
            else if (strncmp(word, TOKEN_SELF_ENCRYPTION_KEY, TOKEN_SELF_ENCRYPTION_KEY_LEN) == 0)
            {
                curr = SELF_ENCRYPTION_KEY;
                memset(word, 0, word_max_len);
                i = 0;
            }
            break;
        }
        case AES_PKAM_PUBLIC_KEY:
        {
            *(atkeysfile->aes_pkam_public_key->key + i++) = c;
            break;
        }
        case AES_PKAM_PRIVATE_KEY:
        {
            *(atkeysfile->aes_pkam_private_key->key + i++) = c;
            break;
        }
        case AES_ENCRYPT_PUBLIC_KEY:
        {
            *(atkeysfile->aes_encrypt_public_key->key + i++) = c;
            break;
        }
        case AES_ENCRYPT_PRIVATE_KEY:
        {
            *(atkeysfile->aes_encrypt_private_key->key + i++) = c;
            break;
        }
        case SELF_ENCRYPTION_KEY:
        {
            *(atkeysfile->self_encryption_key->key + i++) = c;
            break;
        }
        }
        // printf("curr: %d | c: %c | i: %lu | word: %.*s\n", curr, c, i, 50, word);
    }

    fclose(file);
    free(word);

    ret = 0;

    goto exit;

exit:
{
    return ret;
}
}

int atclient_atkeysfile_write(const char *path, const char *atsign, atclient_atkeysfile *atkeysfile)
{
    int ret = 1;

    printf("writing to path: %s\n", path);

    FILE *file = fopen(path, "w+");

    if (file == NULL)
    {
        printf("Error opening file!\n");
        ret = 1;
        goto exit;
    }


    fputs("{\"", file);                                    // {"
    fputs(TOKEN_AES_PKAM_PUBLIC_KEY, file);                // aesPkamPublicKey
    fputs("\":\"", file);                                  // ":"
    fputs(atkeysfile->aes_pkam_public_key->key, file);     // <aesPkamPublicKey>
    fputs("\",\"", file);                                  // ","
    fputs(TOKEN_AES_PKAM_PRIVATE_KEY, file);               // aesPkamPrivateKey
    fputs("\":\"", file);                                  // ":"
    fputs(atkeysfile->aes_pkam_private_key->key, file);    // <aesPkamPrivateKey>
    fputs("\",\"", file);                                  // ","
    fputs(TOKEN_AES_ENCRYPT_PUBLIC_KEY, file);             // aesEncryptPublicKey
    fputs("\":\"", file);                                  // ":"
    fputs(atkeysfile->aes_encrypt_public_key->key, file);  // <aesEncryptPublicKey>
    fputs("\",\"", file);                                  // ","
    fputs(TOKEN_AES_ENCRYPT_PRIVATE_KEY, file);            // aesEncryptPrivateKey
    fputs("\":\"", file);                                  // ":"
    fputs(atkeysfile->aes_encrypt_private_key->key, file); // <aesEncryptPrivateKey>
    fputs("\",\"", file);                                  // ","
    fputs(TOKEN_SELF_ENCRYPTION_KEY, file);                // selfEncryptionKey
    fputs("\":\"", file);                                  // ":"
    fputs(atkeysfile->self_encryption_key->key, file);     // <selfEncryptionKey>
    fputs("\",\"", file);                                  // ","
    fputs(atsign, file);                                   // @alice
    fputs("\":\"", file);                                  // ":"
    fputs(atkeysfile->self_encryption_key->key, file);     // <selfEncryptionKey>
    fputs("\"}", file);                                    // "}


    fclose(file);

    ret = 0;
    goto exit;

exit:
{
    return ret;
}
}

void atclient_atkeysfile_free(atclient_atkeysfile *atkeysfile)
{
    free(atkeysfile->aes_encrypt_private_key->key);
    free(atkeysfile->aes_encrypt_private_key);

    free(atkeysfile->aes_encrypt_public_key->key);
    free(atkeysfile->aes_encrypt_public_key);

    free(atkeysfile->aes_pkam_private_key->key);
    free(atkeysfile->aes_pkam_private_key);

    free(atkeysfile->aes_pkam_public_key->key);
    free(atkeysfile->aes_pkam_public_key);

    free(atkeysfile->self_encryption_key->key);
    free(atkeysfile->self_encryption_key);
}
