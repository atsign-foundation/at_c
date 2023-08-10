#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "at_client.h"

#define ATSIGN "@smoothalligator"

int main()
{
    int ret = 1;
    char path[200];
    strcat(path, "/Users/jeremytubongbanua/.atsign/keys/");
    strcat(path, ATSIGN);
    strcat(path, "_key.atKeys");
    printf("path: %s\n", path);

    atclient_atkeysfile atkeysfile;
    atclient_atkeysfile_init(&atkeysfile);
    printf("done init...\n");

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
    printf("atclient_atkeysfile_write: %d\n", ret);
    if (ret != 0)
    {
        goto exit;
    }

    printf("done write...\n");

    goto exit;

exit:
{
    return ret;
}
}
