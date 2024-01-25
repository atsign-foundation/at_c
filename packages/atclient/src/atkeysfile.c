#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <cJSON/cJSON.h>
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

int atclient_atkeysfile_read(atclient_atkeysfile *atkeysfile, const char *path)
{
    int ret = 1;

    FILE *file = fopen(path, "r");


    const unsigned long readbuflen = 32768;
    char *readbuf = (char *) malloc(sizeof(char) * readbuflen);
    memset(readbuf, 0, readbuflen);

    if (file == NULL)
    {
        printf("Error opening file!\n");
        ret = 1;
        goto exit;
    }

    unsigned long bytes_read = fread(readbuf, sizeof(char), readbuflen, file);
    if (bytes_read == 0)
    {
        printf("Error reading file!\n");
        ret = 1;
        goto exit;
    }

    cJSON *root = cJSON_Parse(readbuf);

    cJSON *aespkamprivatekey = cJSON_GetObjectItem(root, "aesPkamPrivateKey");
    if (aespkamprivatekey == NULL)
    {
        printf("Error reading aesPkamPrivateKey!\n");
        ret = 1;
        goto exit;
    }

    cJSON *aespkampublickey = cJSON_GetObjectItem(root, "aesPkamPublicKey");
    if (aespkampublickey == NULL)
    {
        printf("Error reading aesPkamPublicKey!\n");
        ret = 1;
        goto exit;
    }

    cJSON *aesencryptprivatekey = cJSON_GetObjectItem(root, "aesEncryptPrivateKey");
    if (aesencryptprivatekey == NULL)
    {
        printf("Error reading aesEncryptPrivateKey!\n");
        ret = 1;
        goto exit;
    }

    cJSON *aesencryptpublickey = cJSON_GetObjectItem(root, "aesEncryptPublicKey");
    if (aesencryptpublickey == NULL)
    {
        printf("Error reading aesEncryptPublicKey!\n");
        ret = 1;
        goto exit;
    }

    cJSON *selfencryptionkey = cJSON_GetObjectItem(root, "selfEncryptionKey");
    if (selfencryptionkey == NULL)
    {
        printf("Error reading selfEncryptionKey!\n");
        ret = 1;
        goto exit;
    }

    atkeysfile->aespkamprivatekeyolen = strlen(aespkamprivatekey->valuestring);
    memcpy(atkeysfile->aespkamprivatekeystr, aespkamprivatekey->valuestring, atkeysfile->aespkamprivatekeyolen);

    atkeysfile->aespkampublickeyolen = strlen(aespkampublickey->valuestring);
    memcpy(atkeysfile->aespkampublickeystr, aespkampublickey->valuestring, atkeysfile->aespkampublickeyolen);

    atkeysfile->aesencryptprivatekeyolen = strlen(aesencryptprivatekey->valuestring);
    memcpy(atkeysfile->aesencryptprivatekeystr, aesencryptprivatekey->valuestring, atkeysfile->aesencryptprivatekeyolen);

    atkeysfile->aesencryptpublickeyolen = strlen(aesencryptpublickey->valuestring);
    memcpy(atkeysfile->aesencryptpublickeystr, aesencryptpublickey->valuestring, atkeysfile->aesencryptpublickeyolen);

    atkeysfile->selfencryptionkeyolen = strlen(selfencryptionkey->valuestring);
    memcpy(atkeysfile->selfencryptionkeystr, selfencryptionkey->valuestring, atkeysfile->selfencryptionkeyolen);

    ret = 0; // success

    goto exit;

exit:
{
    fclose(file);
    free(readbuf);
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
