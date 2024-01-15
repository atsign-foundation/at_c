#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "atclient/atkeysfile.h"

#include "cJSON.h"

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
    int ret = 0;
    char *what = "";

    FILE *file = fopen(path, "r");

    if (file == NULL)
    {
        printf("Error opening file!\n");
        ret = 1;
        goto exit1;
    }

    const unsigned long readbuflen = 32768;
    char *readbuf = (char *) malloc(sizeof(char) * readbuflen);
    memset(readbuf, 0, readbuflen);

    unsigned long bytes_read = fread(readbuf, sizeof(char), readbuflen, file);
    if (bytes_read == 0)
    {
        printf("Error reading file!\n");
        ret = 1;
        goto exit2;
    }
    cJSON *root = cJSON_Parse(readbuf);

    if (root == NULL) 
    {
        const char *error_ptr = cJSON_GetErrorPtr();
        if (error_ptr != NULL) 
        {
            what = "it wasn't possible to parse the atKeys file content";
            fprintf(stderr, "Error while parsing atKeys: %s, %s\n", what, error_ptr);
        }
        ret = 1;
        goto exit2;
    }

    atkeysfile->aespkampublickeystr = cJSON_GetObjectItemCaseSensitive(root, "aesPkamPublicKey")->valuestring;
    if (!atkeysfile->aespkampublickeystr) 
    {
        what = "\"aesPkamPublicKey\" wasn't found";
        fprintf(stderr, "Error while parsing atKeys: %s\n", what);
        ret = 1;
        goto exit2;
    }
    atkeysfile->aespkampublickeyolen = strlen(atkeysfile->aespkampublickeystr);

    atkeysfile->aespkamprivatekeystr = cJSON_GetObjectItemCaseSensitive(root, "aesPkamPrivateKey")->valuestring;
    if (!atkeysfile->aespkamprivatekeystr) 
    {
        what = "\"aesPkamPrivateKey\" wasn't found";
        fprintf(stderr, "Error while parsing atKeys: %s\n", what);
        ret = 1;
        goto exit2;
    }
    atkeysfile->aespkamprivatekeyolen = strlen(atkeysfile->aespkamprivatekeystr);

    atkeysfile->aesencryptpublickeystr = cJSON_GetObjectItemCaseSensitive(root, "aesEncryptPublicKey")->valuestring;
    if (!atkeysfile->aesencryptpublickeystr) 
    {
        what = "\"aesEncryptPublicKey\" wasn't found";
        fprintf(stderr, "Error while parsing atKeys: %s\n", what);
        ret = 1;
        goto exit2;
    }
    atkeysfile->aesencryptpublickeyolen = strlen(atkeysfile->aesencryptpublickeystr);

    atkeysfile->aesencryptprivatekeystr = cJSON_GetObjectItemCaseSensitive(root, "aesEncryptPrivateKey")->valuestring;
    if (!atkeysfile->aesencryptprivatekeystr) 
    {
        what = "\"aesEncryptPrivateKey\" wasn't found";
        fprintf(stderr, "Error while parsing atKeys: %s\n", what);
        ret = 1;
        goto exit2;
    }
    atkeysfile->aesencryptprivatekeyolen = strlen(atkeysfile->aesencryptprivatekeystr);

    atkeysfile->selfencryptionkeystr = cJSON_GetObjectItemCaseSensitive(root, "selfEncryptionKey")->valuestring;
    if (!atkeysfile->selfencryptionkeystr) 
    {
        what = "\"selfEncryptionKey\" wasn't found";
        fprintf(stderr, "Error while parsing atKeys: %s\n", what);
        ret = 1;
        goto exit2;
    }
    atkeysfile->selfencryptionkeyolen = strlen(atkeysfile->selfencryptionkeystr);


    goto exit2;

exit1:
{
    fclose(file);
    return ret;
}

exit2:
{
    fclose(file);
    free(readbuf);
    return ret;
}
}

int atclient_atkeysfile_write(atclient_atkeysfile *keys, const char *directory, const char *atsign)
{
    int ret = 0;
    char file_path[256];
    snprintf(file_path, sizeof(file_path), "%s/%s_key.atKeys", directory, atsign);

    cJSON *root = cJSON_CreateObject();

    cJSON_AddStringToObject(root, "aesPkamPublicKey", keys->aespkampublickeystr);
    cJSON_AddStringToObject(root, "aesPkamPrivateKey", keys->aespkamprivatekeystr);
    cJSON_AddStringToObject(root, "aesEncryptPublicKey", keys->aesencryptpublickeystr);
    cJSON_AddStringToObject(root, "aesEncryptPrivateKey", keys->aesencryptprivatekeystr);
    cJSON_AddStringToObject(root, "selfEncryptionKey", keys->selfencryptionkeystr);
    cJSON_AddStringToObject(root, atsign, keys->selfencryptionkeystr);

    char *json_string = cJSON_Print(root);

    FILE *file = fopen(file_path, "w");
    if (file == NULL) 
    {
        fprintf(stderr, "Error opening file!\n");
        ret = 1;
        goto exit2;    
    }

    goto exit1;

exit1:
{       
    fclose(file);
    cJSON_Delete(root);
    free(json_string);
    return ret;
}
exit2:
{       
    cJSON_Delete(root);
    free(json_string);
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
