#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "atclient/atkeysfile.h"

#define BASE64_ENCRYPTED_KEY_BUFFER_SIZE 4096

void atclient_atkeysfile_init(atclient_atkeysfile *atkeysfile)
{
    memset(atkeysfile, 0, sizeof(atclient_atkeysfile));

    atkeysfile->aespkamprivatekeylen = BASE64_ENCRYPTED_KEY_BUFFER_SIZE;
    atkeysfile->aespkamprivatekeystr = (char *)malloc(sizeof(char) * atkeysfile->aespkamprivatekeylen);
    memset(atkeysfile->aespkamprivatekeystr, 0, atkeysfile->aespkamprivatekeylen);
    atkeysfile->aespkamprivatekeyolen = 0;

    atkeysfile->aespkampublickeylen = BASE64_ENCRYPTED_KEY_BUFFER_SIZE;
    atkeysfile->aespkampublickeystr = (char *)malloc(sizeof(char) * atkeysfile->aespkampublickeylen);
    memset(atkeysfile->aespkampublickeystr, 0, atkeysfile->aespkampublickeylen);
    atkeysfile->aespkampublickeyolen = 0;

    atkeysfile->aesencryptprivatekeylen = BASE64_ENCRYPTED_KEY_BUFFER_SIZE;
    atkeysfile->aesencryptprivatekeystr = (char *)malloc(sizeof(char) * atkeysfile->aesencryptprivatekeylen);
    memset(atkeysfile->aesencryptprivatekeystr, 0, atkeysfile->aesencryptprivatekeylen);
    atkeysfile->aesencryptprivatekeyolen = 0;

    atkeysfile->aesencryptpublickeylen = BASE64_ENCRYPTED_KEY_BUFFER_SIZE;
    atkeysfile->aesencryptpublickeystr = (char *)malloc(sizeof(char) * atkeysfile->aesencryptpublickeylen);
    memset(atkeysfile->aesencryptpublickeystr, 0, atkeysfile->aesencryptpublickeylen);
    atkeysfile->aesencryptpublickeyolen = 0;

    atkeysfile->selfencryptionkeylen = BASE64_ENCRYPTED_KEY_BUFFER_SIZE;
    atkeysfile->selfencryptionkeystr = (char *)malloc(sizeof(char) * atkeysfile->selfencryptionkeylen);
    memset(atkeysfile->selfencryptionkeystr, 0, atkeysfile->selfencryptionkeylen);
    atkeysfile->selfencryptionkeyolen = 0;
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
    char *read_buf = (char *) malloc(sizeof(char) * read_buf_len);
    memset(read_buf, 0, read_buf_len);

    unsigned long bytes_read = fread(read_buf, sizeof(char), read_buf_len, file);
    if (bytes_read == 0)
    {
        printf("Error reading file!\n");
        ret = 1;
        goto exit;
    }

    ret = extract_json_string(read_buf, "aesPkamPublicKey", atkeysfile->aespkampublickeystr, atkeysfile->aespkampublickeylen);
    if (ret != 0)
    {
        printf("Error extracting aesPkamPublicKey\n");
        ret = 1;
        goto exit;
    }
    atkeysfile->aespkampublickeyolen = strlen(atkeysfile->aespkampublickeystr);

    ret = extract_json_string(read_buf, "aesPkamPrivateKey", atkeysfile->aespkamprivatekeystr, atkeysfile->aespkamprivatekeylen);
    if (ret != 0)
    {
        printf("Error extracting aesPkamPrivateKey\n");
        ret = 1;
        goto exit;
    }
    atkeysfile->aespkamprivatekeyolen = strlen(atkeysfile->aespkamprivatekeystr);

    ret = extract_json_string(read_buf, "aesEncryptPublicKey", atkeysfile->aesencryptpublickeystr, atkeysfile->aesencryptpublickeylen);
    if (ret != 0)
    {
        printf("Error extracting aesEncryptPublicKey\n");
        ret = 1;
        goto exit;
    }
    atkeysfile->aesencryptpublickeyolen = strlen(atkeysfile->aesencryptpublickeystr);

    ret = extract_json_string(read_buf, "aesEncryptPrivateKey", atkeysfile->aesencryptprivatekeystr, atkeysfile->aesencryptprivatekeylen);
    if (ret != 0)
    {
        printf("Error extracting aesEncryptPrivateKey\n");
        ret = 1;
        goto exit;
    }
    atkeysfile->aesencryptprivatekeyolen = strlen(atkeysfile->aesencryptprivatekeystr);

    ret = extract_json_string(read_buf, "selfEncryptionKey", atkeysfile->selfencryptionkeystr, atkeysfile->selfencryptionkeylen);
    if (ret != 0)
    {
        printf("Error extracting selfEncryptionKey\n");
        ret = 1;
        goto exit;
    }
    atkeysfile->selfencryptionkeyolen = strlen(atkeysfile->selfencryptionkeystr);


    goto exit;

exit:
{
    fclose(file);
    free(read_buf);
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
    free(atkeysfile->aespkamprivatekeystr);
    free(atkeysfile->aespkampublickeystr);
    free(atkeysfile->aesencryptprivatekeystr);
    free(atkeysfile->aesencryptpublickeystr);
}
