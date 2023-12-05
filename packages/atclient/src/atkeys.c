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
        (unsigned char *)atkeys->pkampublickeystr, atkeys->pkampublickeylen, &(atkeys->pkampublickeyolen));
    if (ret != 0)
    {
        goto exit;
    }
    memset(iv, 0, sizeof(unsigned char) * IV_SIZE);

    // 1c. pkam private key
    ret = atchops_aesctr_decrypt(
        atkeys->selfencryptionkeystr, atkeys->selfencryptionkeyolen, ATCHOPS_AES_256, iv,
        atkeysfile.aespkamprivatekeystr, atkeysfile.aespkamprivatekeyolen,
        (unsigned char *)atkeys->pkamprivatekeystr, atkeys->pkamprivatekeylen, &(atkeys->pkamprivatekeyolen));
    if (ret != 0)
    {
        goto exit;
    }
    memset(iv, 0, sizeof(unsigned char) * IV_SIZE);

    // 1d. encrypt public key
    ret = atchops_aesctr_decrypt(
        atkeys->selfencryptionkeystr, atkeys->selfencryptionkeyolen, ATCHOPS_AES_256, iv,
        atkeysfile.aesencryptpublickeystr, atkeysfile.aesencryptpublickeyolen,
        (unsigned char *)atkeys->encryptpublickeystr, atkeys->encryptpublickeylen, &(atkeys->encryptpublickeyolen));
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

// Function to copy atclient_atkeys
void copy_atkeys(atclient_atkeys *dest, const atclient_atkeys *src)
{
    // Copy each member of the struct
    dest->pkampublickeylen = src->pkampublickeylen;
    dest->pkamprivatekeylen = src->pkamprivatekeylen;
    dest->encryptpublickeylen = src->encryptpublickeylen;
    dest->encryptprivatekeylen = src->encryptprivatekeylen;
    dest->selfencryptionkeylen = src->selfencryptionkeylen;

    // Copy pkam public key
    if (dest->pkampublickeylen > 0)
    {
        free(dest->pkampublickeystr);
        dest->pkampublickeystr = (char *)malloc(sizeof(char) * dest->pkampublickeylen);
        strncpy(dest->pkampublickeystr, src->pkampublickeystr, dest->pkampublickeylen);
    }

    // Copy pkam private key
    if (dest->pkamprivatekeylen > 0)
    {
        free(dest->pkamprivatekeystr);
        dest->pkamprivatekeystr = (char *)malloc(sizeof(char) * dest->pkamprivatekeylen);
        strncpy(dest->pkamprivatekeystr, src->pkamprivatekeystr, dest->pkamprivatekeylen);
    }

    // Copy encrypt public key
    if (dest->encryptpublickeylen > 0)
    {
        free(dest->encryptpublickeystr);
        dest->encryptpublickeystr = (char *)malloc(sizeof(char) * dest->encryptpublickeylen);
        strncpy(dest->encryptpublickeystr, src->encryptpublickeystr, dest->encryptpublickeylen);
    }

    // Copy encrypt private key
    if (dest->encryptprivatekeylen > 0)
    {
        free(dest->encryptprivatekeystr);
        dest->encryptprivatekeystr = (char *)malloc(sizeof(char) * dest->encryptprivatekeylen);
        strncpy(dest->encryptprivatekeystr, src->encryptprivatekeystr, dest->encryptprivatekeylen);
    }

    // Copy self encryption key
    if (dest->selfencryptionkeylen > 0)
    {
        free(dest->selfencryptionkeystr);
        dest->selfencryptionkeystr = (char *)malloc(sizeof(char) * dest->selfencryptionkeylen);
        strncpy(dest->selfencryptionkeystr, src->selfencryptionkeystr, dest->selfencryptionkeylen);
    }

    // Copy RSA key parameters
    memcpy(&(dest->pkampublickey), &(src->pkampublickey), sizeof(atchops_rsakey_publickey));
    memcpy(&(dest->pkamprivatekey), &(src->pkamprivatekey), sizeof(atchops_rsakey_privatekey));
    memcpy(&(dest->encryptpublickey), &(src->encryptpublickey), sizeof(atchops_rsakey_publickey));
    memcpy(&(dest->encryptprivatekey), &(src->encryptprivatekey), sizeof(atchops_rsakey_privatekey));

    // pkam public key
    dest->pkampublickey.n.value = (unsigned char *)malloc(sizeof(unsigned char) * dest->pkampublickey.n.len);
    memcpy(dest->pkampublickey.n.value, src->pkampublickey.n.value, dest->pkampublickey.n.len);

    dest->pkampublickey.e.value = (unsigned char *)malloc(sizeof(unsigned char) * dest->pkampublickey.e.len);
    memcpy(dest->pkampublickey.e.value, src->pkampublickey.e.value, dest->pkampublickey.e.len);

    // pkam private key
    dest->pkamprivatekey.n.value = (unsigned char *)malloc(sizeof(unsigned char) * dest->pkamprivatekey.n.len);
    memcpy(dest->pkamprivatekey.n.value, src->pkamprivatekey.n.value, dest->pkamprivatekey.n.len);

    dest->pkamprivatekey.e.value = (unsigned char *)malloc(sizeof(unsigned char) * dest->pkamprivatekey.e.len);
    memcpy(dest->pkamprivatekey.e.value, src->pkamprivatekey.e.value, dest->pkamprivatekey.e.len);

    dest->pkamprivatekey.d.value = (unsigned char *)malloc(sizeof(unsigned char) * dest->pkamprivatekey.d.len);
    memcpy(dest->pkamprivatekey.d.value, src->pkamprivatekey.d.value, dest->pkamprivatekey.d.len);

    dest->pkamprivatekey.p.value = (unsigned char *)malloc(sizeof(unsigned char) * dest->pkamprivatekey.p.len);
    memcpy(dest->pkamprivatekey.p.value, src->pkamprivatekey.p.value, dest->pkamprivatekey.p.len);

    dest->pkamprivatekey.q.value = (unsigned char *)malloc(sizeof(unsigned char) * dest->pkamprivatekey.q.len);
    memcpy(dest->pkamprivatekey.q.value, src->pkamprivatekey.q.value, dest->pkamprivatekey.q.len);

    // encrypt public key
    dest->encryptpublickey.n.value = (unsigned char *)malloc(sizeof(unsigned char) * dest->encryptpublickey.n.len);
    memcpy(dest->encryptpublickey.n.value, src->encryptpublickey.n.value, dest->encryptpublickey.n.len);

    dest->encryptpublickey.e.value = (unsigned char *)malloc(sizeof(unsigned char) * dest->encryptpublickey.e.len);
    memcpy(dest->encryptpublickey.e.value, src->encryptpublickey.e.value, dest->encryptpublickey.e.len);

    // encrypt private key
    dest->encryptprivatekey.n.value = (unsigned char *)malloc(sizeof(unsigned char) * dest->encryptprivatekey.n.len);
    memcpy(dest->encryptprivatekey.n.value, src->encryptprivatekey.n.value, dest->encryptprivatekey.n.len);

    dest->encryptprivatekey.e.value = (unsigned char *)malloc(sizeof(unsigned char) * dest->encryptprivatekey.e.len);
    memcpy(dest->encryptprivatekey.e.value, src->encryptprivatekey.e.value, dest->encryptprivatekey.e.len);

    dest->encryptprivatekey.d.value = (unsigned char *)malloc(sizeof(unsigned char) * dest->encryptprivatekey.d.len);
    memcpy(dest->encryptprivatekey.d.value, src->encryptprivatekey.d.value, dest->encryptprivatekey.d.len);

    dest->encryptprivatekey.p.value = (unsigned char *)malloc(sizeof(unsigned char) * dest->encryptprivatekey.p.len);
    memcpy(dest->encryptprivatekey.p.value, src->encryptprivatekey.p.value, dest->encryptprivatekey.p.len);

    dest->encryptprivatekey.q.value = (unsigned char *)malloc(sizeof(unsigned char) * dest->encryptprivatekey.q.len);
    memcpy(dest->encryptprivatekey.q.value, src->encryptprivatekey.q.value, dest->encryptprivatekey.q.len);
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