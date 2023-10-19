#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include "atchops/aes_ctr.h"
#include "atclient/atkeys.h"

#define BUFFER_SIZE 4096 // the max size of an RSA key base 64 encoded

void atclient_atkeys_init(atclient_atkeys *atkeys)
{
    memset(atkeys, 0, sizeof(atclient_atkeys));

    atkeys->pkampublickeylen = BUFFER_SIZE;
    atkeys->pkampublickeystr = (unsigned char *) malloc(sizeof(char) * atkeys->pkampublickeylen);
    atkeys->pkampublickeyolen = 0;
    memset(atkeys->pkampublickeystr, 0, atkeys->pkampublickeylen);

    atkeys->pkamprivatekeylen = BUFFER_SIZE;
    atkeys->pkamprivatekeystr = (unsigned char *) malloc(sizeof(char) * atkeys->pkamprivatekeylen);
    atkeys->pkamprivatekeyolen = 0;
    memset(atkeys->pkamprivatekeystr, 0, atkeys->pkamprivatekeylen);

    atkeys->encryptpublickeylen = BUFFER_SIZE;
    atkeys->encryptpublickeystr = (unsigned char *) malloc(sizeof(char) * atkeys->encryptpublickeylen);
    atkeys->encryptpublickeyolen = 0;
    memset(atkeys->encryptpublickeystr, 0, atkeys->encryptpublickeylen);

    atkeys->encryptprivatekeylen = BUFFER_SIZE;
    atkeys->encryptprivatekeystr = (unsigned char *) malloc(sizeof(char) * atkeys->encryptprivatekeylen);
    atkeys->encryptprivatekeyolen = 0;
    memset(atkeys->encryptprivatekeystr, 0, atkeys->encryptprivatekeylen);

    atkeys->selfencryptionkeylen = BUFFER_SIZE;
    atkeys->selfencryptionkeystr = (unsigned char *) malloc(sizeof(char) * atkeys->selfencryptionkeylen);
    atkeys->selfencryptionkeyolen = 0;
    memset(atkeys->selfencryptionkeystr, 0, atkeys->selfencryptionkeylen);
}

int atclient_atkeys_populate(atclient_atkeys *atkeys, atclient_atkeysfile atkeysfile)
{
    int ret = 1;

    unsigned char *iv = (unsigned char *) malloc(sizeof(unsigned char) * 16);
    memset(iv, 0, sizeof(unsigned char) * 16);

    const unsigned long recvlen = 32768;
    unsigned char recv = (unsigned char *) malloc(sizeof(unsigned char) * recvlen);
    unsigned long olen = 0;

    // 1. self encryption key
    strncpy(atkeys->selfencryptionkeystr, atkeysfile.selfencryptionkeystr, atkeysfile.selfencryptionkeyolen);
    atkeys->selfencryptionkeyolen = atkeysfile.selfencryptionkeyolen;

    // 2. pkam public key
    ret = atchops_aes_ctr_decrypt(
        atkeys->selfencryptionkeystr, atkeys->selfencryptionkeyolen, ATCHOPS_AES_256, iv,
        atkeysfile.aespkampublickeystr, atkeysfile.aespkampublickeyolen,
        atkeys->pkampublickeystr, atkeys->pkampublickeylen, &(atkeys->pkampublickeyolen));

    printf("pkam public key str: %s\n", atkeys->pkampublickeystr);
    if(ret != 0)
    {
        goto exit;
    }
    memset(iv, 0, sizeof(unsigned char) * 16);

    // 3. pkam private key
    ret = atchops_aes_ctr_decrypt(
        atkeys->selfencryptionkeystr, atkeys->selfencryptionkeyolen, ATCHOPS_AES_256, iv,
        atkeysfile.aespkamprivatekeystr, atkeysfile.aespkamprivatekeyolen,
        atkeys->pkamprivatekeystr, atkeys->pkamprivatekeylen, &(atkeys->pkamprivatekeyolen));
    if(ret != 0)
    {
        goto exit;
    }
    memset(iv, 0, sizeof(unsigned char) * 16);

    // 4. encrypt public key
    ret = atchops_aes_ctr_decrypt(
        atkeys->selfencryptionkeystr, atkeys->selfencryptionkeyolen, ATCHOPS_AES_256, iv,
        atkeysfile.aesencryptpublickeystr, atkeysfile.aesencryptpublickeyolen,
        atkeys->encryptpublickeystr, atkeys->encryptpublickeylen, &(atkeys->encryptpublickeyolen));

    if(ret != 0)
    {
        goto exit;
    }
    memset(iv, 0, sizeof(unsigned char) * 16);

    // 5. encrypt private key
    ret = atchops_aes_ctr_decrypt(
        atkeys->selfencryptionkeystr, atkeys->selfencryptionkeyolen, ATCHOPS_AES_256, iv,
        atkeysfile.aesencryptprivatekeystr, atkeysfile.aesencryptprivatekeyolen,
        atkeys->encryptprivatekeystr, atkeys->encryptprivatekeylen, &(atkeys->encryptprivatekeyolen));
    if(ret != 0)
    {
        goto exit;
    }

    // populate rsa structs
    printf("PKAM PUBLIC KEY STR: %s\n", atkeys->pkampublickeystr);
    ret = atchops_rsa_populate_publickey(&(atkeys->pkampublickey), atkeys->pkampublickeystr, atkeys->pkampublickeyolen);
    printf("atchops_rsa_populate_privatekey: %d\n", ret);
    if(ret != 0)
    {
        goto exit;
    }

    ret = atchops_rsa_populate_privatekey(&(atkeys->pkamprivatekey), atkeys->pkamprivatekeystr, atkeys->pkamprivatekeyolen);
    printf("atchops_rsa_populate_privatekey: %d\n", ret);
    if(ret != 0)
    {
        goto exit;
    }

    ret = atchops_rsa_populate_privatekey(&(atkeys->encryptprivatekey), atkeys->encryptprivatekeystr, atkeys->encryptprivatekeyolen);
    printf("atchops_rsa_populate_privatekey: %d\n", ret);
    if(ret != 0)
    {
        goto exit;
    }

    ret = atchops_rsa_populate_publickey(&(atkeys->encryptpublickey), atkeys->encryptpublickeystr, atkeys->encryptpublickeyolen);
    printf("atchops_rsa_populate_privatekey: %d\n", ret);
    if(ret != 0)
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
    return; // TODO: implement
}