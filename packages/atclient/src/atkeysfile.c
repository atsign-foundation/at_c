#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "atclient/atkeysfile.h"

#define BASE64_ENCRYPTED_KEY_BUFFER_SIZE 4096

void atclient_atkeysfile_init(atclient_atkeysfile *atkeysfile)
{
    memset(atkeysfile, 0, sizeof(atclient_atkeysfile));

    atkeysfile->aes_pkam_private_key_len = BASE64_ENCRYPTED_KEY_BUFFER_SIZE;
    atkeysfile->aes_pkam_private_key = (char *)malloc(sizeof(char) * atkeysfile->aes_pkam_private_key_len);
    memset(atkeysfile->aes_pkam_private_key, 0, atkeysfile->aes_pkam_private_key_len);
    atkeysfile->aes_pkam_private_key_olen = 0;

    atkeysfile->aes_pkam_public_key_len = BASE64_ENCRYPTED_KEY_BUFFER_SIZE;
    atkeysfile->aes_pkam_public_key = (char *)malloc(sizeof(char) * atkeysfile->aes_pkam_public_key_len);
    memset(atkeysfile->aes_pkam_public_key, 0, atkeysfile->aes_pkam_public_key_len);
    atkeysfile->aes_pkam_public_key_olen = 0;

    atkeysfile->aes_encrypt_private_key_len = BASE64_ENCRYPTED_KEY_BUFFER_SIZE;
    atkeysfile->aes_encrypt_private_key = (char *)malloc(sizeof(char) * atkeysfile->aes_encrypt_private_key_len);
    memset(atkeysfile->aes_encrypt_private_key, 0, atkeysfile->aes_encrypt_private_key_len);
    atkeysfile->aes_encrypt_private_key_olen = 0;

    atkeysfile->aes_encrypt_public_key_len = BASE64_ENCRYPTED_KEY_BUFFER_SIZE;
    atkeysfile->aes_encrypt_public_key = (char *)malloc(sizeof(char) * atkeysfile->aes_encrypt_public_key_len);
    memset(atkeysfile->aes_encrypt_public_key, 0, atkeysfile->aes_encrypt_public_key_len);
    atkeysfile->aes_encrypt_public_key_olen = 0;

    atkeysfile->self_encryption_key_len = BASE64_ENCRYPTED_KEY_BUFFER_SIZE;
    atkeysfile->self_encryption_key = (char *)malloc(sizeof(char) * atkeysfile->self_encryption_key_len);
    memset(atkeysfile->self_encryption_key, 0, atkeysfile->self_encryption_key_len);
    atkeysfile->self_encryption_key_olen = 0;
}

static int extract_json_string(const char *json, const char *key, char *buffer, unsigned long bufferlen)
{
    // todo: error handling
    const char *keyStart = strstr(json, key);
    if (keyStart == NULL)
    {
        return 1; // Key not found
    }

    // move ptr to start of value
    keyStart += strlen(key) + 3; // +1 for the colon

    char c;
    int j = 0;
    while ((c = *keyStart) != '\0' && c != '\"' && c != '\n' && j < bufferlen)
    {
        *(buffer + j) = c;
        j++;
        keyStart++;
    }

    return 0;
}

int atclient_atkeysfile_read(atclient_atkeysfile *atkeysfile, const char *path)
{
    int ret = 1;

    FILE *file = fopen(path, "r");

    if (file == NULL)
    {
        printf("Error opening file!\n");
        ret = 1;
        goto exit;
    }

    const unsigned long read_buf_len = 32768;
    char *read_buf = (char *)malloc(sizeof(char) * read_buf_len);
    memset(read_buf, 0, read_buf_len);

    unsigned long bytes_read = fread(read_buf, sizeof(char), read_buf_len, file);
    if (bytes_read == 0)
    {
        printf("Error reading file!\n");
        ret = 1;
        goto exit;
    }

    ret = extract_json_string(read_buf, "aesPkamPublicKey", atkeysfile->aes_pkam_public_key, atkeysfile->aes_pkam_public_key_len);
    if (ret != 0)
    {
        printf("Error extracting aesPkamPublicKey\n");
        ret = 1;
        goto exit;
    }
    atkeysfile->aes_pkam_public_key_olen = strlen(atkeysfile->aes_pkam_public_key);

    ret = extract_json_string(read_buf, "aesPkamPrivateKey", atkeysfile->aes_pkam_private_key, atkeysfile->aes_pkam_private_key_len);
    if (ret != 0)
    {
        printf("Error extracting aesPkamPrivateKey\n");
        ret = 1;
        goto exit;
    }
    atkeysfile->aes_pkam_private_key_olen = strlen(atkeysfile->aes_pkam_private_key);

    ret = extract_json_string(read_buf, "aesEncryptPublicKey", atkeysfile->aes_encrypt_public_key, atkeysfile->aes_encrypt_public_key_len);
    if (ret != 0)
    {
        printf("Error extracting aesEncryptPublicKey\n");
        ret = 1;
        goto exit;
    }
    atkeysfile->aes_encrypt_public_key_olen = strlen(atkeysfile->aes_encrypt_public_key);

    ret = extract_json_string(read_buf, "aesEncryptPrivateKey", atkeysfile->aes_encrypt_private_key, atkeysfile->aes_encrypt_private_key_len);
    if (ret != 0)
    {
        printf("Error extracting aesEncryptPrivateKey\n");
        ret = 1;
        goto exit;
    }
    atkeysfile->aes_encrypt_private_key_olen = strlen(atkeysfile->aes_encrypt_private_key);

    ret = extract_json_string(read_buf, "selfEncryptionKey", atkeysfile->self_encryption_key, atkeysfile->self_encryption_key_len);
    if (ret != 0)
    {
        printf("Error extracting selfEncryptionKey\n");
        ret = 1;
        goto exit;
    }
    atkeysfile->self_encryption_key_olen = strlen(atkeysfile->self_encryption_key);

    fclose(file);
    free(read_buf);

    goto exit;

exit:
{
    return ret;
}
}

int atclient_atkeysfile_write(atclient_atkeysfile *atkeysfile, const char *path, const char *atsign)
{
    int ret = 1;

    // TODO: implement

    goto exit;

exit:
{
    return ret;
}
}

void atclient_atkeysfile_free(atclient_atkeysfile *atkeysfile)
{
    free(atkeysfile->aes_pkam_private_key);
    free(atkeysfile->aes_pkam_public_key);
    free(atkeysfile->aes_encrypt_private_key);
    free(atkeysfile->aes_encrypt_public_key);
}
