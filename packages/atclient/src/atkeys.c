#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "atchops/aesctr.h"
#include "atchops/rsakey.h"
#include "atclient/atkeys.h"

#define BUFFER_SIZE 4096 // the max size of an RSA key base 64 encoded
#define IV_SIZE 16       // the size of the IV

void atclient_atkeys_init(atclient_atkeys *atkeys)
{
    memset(atkeys, 0, sizeof(atclient_atkeys));

    atkeys->pkampublickeylen = BUFFER_SIZE;
    atkeys->pkampublickeystr = (char *)malloc(sizeof(char) * atkeys->pkampublickeylen);
    memset(atkeys->pkampublickeystr, 0, atkeys->pkampublickeylen);
    atkeys->pkampublickeyolen = 0;
    atchops_rsakey_init_publickey(&(atkeys->pkampublickey));

    atkeys->pkamprivatekeylen = BUFFER_SIZE;
    atkeys->pkamprivatekeystr = (char *)malloc(sizeof(char) * atkeys->pkamprivatekeylen);
    memset(atkeys->pkamprivatekeystr, 0, atkeys->pkamprivatekeylen);
    atkeys->pkamprivatekeyolen = 0;
    atchops_rsakey_init_privatekey(&(atkeys->pkamprivatekey));

    atkeys->encryptpublickeylen = BUFFER_SIZE;
    atkeys->encryptpublickeystr = (char *)malloc(sizeof(char) * atkeys->encryptpublickeylen);
    memset(atkeys->encryptpublickeystr, 0, atkeys->encryptpublickeylen);
    atkeys->encryptpublickeyolen = 0;
    atchops_rsakey_init_publickey(&(atkeys->encryptpublickey));

    atkeys->encryptprivatekeylen = BUFFER_SIZE;
    atkeys->encryptprivatekeystr = (char *)malloc(sizeof(char) * atkeys->encryptprivatekeylen);
    memset(atkeys->encryptprivatekeystr, 0, atkeys->encryptprivatekeylen);
    atkeys->encryptprivatekeyolen = 0;
    atchops_rsakey_init_privatekey(&(atkeys->encryptprivatekey));

    atkeys->selfencryptionkeylen = BUFFER_SIZE;
    atkeys->selfencryptionkeystr = (char *)malloc(sizeof(char) * atkeys->selfencryptionkeylen);
    memset(atkeys->selfencryptionkeystr, 0, atkeys->selfencryptionkeylen);
    atkeys->selfencryptionkeyolen = 0;
}

int atclient_atkeys_populate(atclient_atkeys *atkeys, atclient_atkeysfile atkeysfile)
{
    int ret = 1;

    unsigned char *iv = (unsigned char *)malloc(sizeof(unsigned char) * IV_SIZE);
    memset(iv, 0, sizeof(unsigned char) * IV_SIZE);

    const unsigned long recvlen = 32768;
    unsigned char *recv = (unsigned char *)malloc(sizeof(unsigned char) * recvlen);
    unsigned long olen = 0;

    // 1. decrypt *.atKeys and populate atkeys struct

    // 1a. self encryption key
    memcpy(atkeys->selfencryptionkeystr, atkeysfile.selfencryptionkeystr, atkeysfile.selfencryptionkeyolen);
    atkeys->selfencryptionkeyolen = atkeysfile.selfencryptionkeyolen;

    // 1b. pkam public key
    ret = atchops_aesctr_decrypt(
        atkeys->selfencryptionkeystr, atkeys->selfencryptionkeyolen, ATCHOPS_AES_256, iv,
        atkeysfile.aespkampublickeystr, atkeysfile.aespkampublickeyolen,
        (unsigned char *) atkeys->pkampublickeystr, atkeys->pkampublickeylen, &(atkeys->pkampublickeyolen));
    if (ret != 0)
    {
        goto exit;
    }
    memset(iv, 0, sizeof(unsigned char) * IV_SIZE);

    // 1c. pkam private key
    ret = atchops_aesctr_decrypt(
        atkeys->selfencryptionkeystr, atkeys->selfencryptionkeyolen, ATCHOPS_AES_256, iv,
        atkeysfile.aespkamprivatekeystr, atkeysfile.aespkamprivatekeyolen,
        (unsigned char *) atkeys->pkamprivatekeystr, atkeys->pkamprivatekeylen, &(atkeys->pkamprivatekeyolen));
    if (ret != 0)
    {
        goto exit;
    }
    memset(iv, 0, sizeof(unsigned char) * IV_SIZE);

    // 1d. encrypt public key
    ret = atchops_aesctr_decrypt(
        atkeys->selfencryptionkeystr, atkeys->selfencryptionkeyolen, ATCHOPS_AES_256, iv,
        atkeysfile.aesencryptpublickeystr, atkeysfile.aesencryptpublickeyolen,
        (unsigned char *) atkeys->encryptpublickeystr, atkeys->encryptpublickeylen, &(atkeys->encryptpublickeyolen));
    if (ret != 0)
    {
        goto exit;
    }
    memset(iv, 0, sizeof(unsigned char) * IV_SIZE);

    // 1e. encrypt private key
    ret = atchops_aesctr_decrypt(
        atkeys->selfencryptionkeystr, atkeys->selfencryptionkeyolen, ATCHOPS_AES_256, iv,
        atkeysfile.aesencryptprivatekeystr, atkeysfile.aesencryptprivatekeyolen,
        atkeys->encryptprivatekeystr, atkeys->encryptprivatekeylen, &(atkeys->encryptprivatekeyolen));
    if (ret != 0)
    {
        goto exit;
    }

    // 2. populate rsa structs in atkeys struct (4 keys)

    // 2a. pkam public key
    ret = atchops_rsakey_populate_publickey(&(atkeys->pkampublickey), atkeys->pkampublickeystr, atkeys->pkampublickeyolen);
    // printf("pkam public key population: %d\n", ret);
    if (ret != 0)
    {
        goto exit;
    }

    ret = atchops_rsakey_populate_privatekey(&(atkeys->pkamprivatekey), atkeys->pkamprivatekeystr, atkeys->pkamprivatekeyolen);
    // printf("pkam private key population: %d\n", ret);
    if (ret != 0)
    {
        goto exit;
    }

    ret = atchops_rsakey_populate_privatekey(&(atkeys->encryptprivatekey), atkeys->encryptprivatekeystr, atkeys->encryptprivatekeyolen);
    // printf("atchops_rsa_populate_privatekey: %d\n", ret);
    if (ret != 0)
    {
        goto exit;
    }

    ret = atchops_rsakey_populate_publickey(&(atkeys->encryptpublickey), atkeys->encryptpublickeystr, atkeys->encryptpublickeyolen);
    // printf("atchops_rsa_populate_privatekey: %d\n", ret);
    if (ret != 0)
    {
        goto exit;
    }

    goto exit;

exit:
{
    free(iv);
    free(recv);
    return ret;
}
}

void atclient_atkeys_free(atclient_atkeys *atkeys)
{
    free(atkeys->pkampublickeystr);
    free(atkeys->pkamprivatekeystr);
    free(atkeys->encryptpublickeystr);
    free(atkeys->encryptprivatekeystr);
    free(atkeys->selfencryptionkeystr);
    atchops_rsakey_free_publickey(&(atkeys->pkampublickey));
    atchops_rsakey_free_privatekey(&(atkeys->pkamprivatekey));
    atchops_rsakey_free_publickey(&(atkeys->encryptpublickey));
    atchops_rsakey_free_privatekey(&(atkeys->encryptprivatekey));
}