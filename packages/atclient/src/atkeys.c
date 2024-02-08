#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <atchops/iv.h>
#include <atchops/aesctr.h>
#include <atchops/rsakey.h>
#include "atlogger/atlogger.h"
#include "atclient/atkeys.h"
#include "atclient/atstr.h"
#include "atclient/constants.h"

#define TAG "atkeys"

void atclient_atkeys_init(atclient_atkeys *atkeys)
{
    memset(atkeys, 0, sizeof(atclient_atkeys));

    atclient_atstr_init(&(atkeys->pkampublickeystr), ATCLIENT_CONSTANTS_DECRYPTED_BASE64_RSA_KEY_BUFFER_SIZE);
    atchops_rsakey_publickey_init(&(atkeys->pkampublickey));

    atclient_atstr_init(&(atkeys->pkamprivatekeystr), ATCLIENT_CONSTANTS_DECRYPTED_BASE64_RSA_KEY_BUFFER_SIZE);
    atchops_rsakey_privatekey_init(&(atkeys->pkamprivatekey));

    atclient_atstr_init(&(atkeys->encryptpublickeystr), ATCLIENT_CONSTANTS_DECRYPTED_BASE64_RSA_KEY_BUFFER_SIZE);
    atchops_rsakey_publickey_init(&(atkeys->encryptpublickey));

    atclient_atstr_init(&(atkeys->encryptprivatekeystr), ATCLIENT_CONSTANTS_DECRYPTED_BASE64_RSA_KEY_BUFFER_SIZE);
    atchops_rsakey_privatekey_init(&(atkeys->encryptprivatekey));

    atclient_atstr_init(&(atkeys->selfencryptionkeystr), ATCLIENT_CONSTANTS_DECRYPTED_BASE64_RSA_KEY_BUFFER_SIZE);
}

int atclient_atkeys_populate_from_strings(atclient_atkeys *atkeys,
    const char *aespkampublickeystr,
    const unsigned long aespkampublickeylen,
    const char *aespkamprivatekeystr,
    const unsigned long aespkamprivatekeylen,
    const char *aesencryptpublickeystr,
    const unsigned long aesencryptpublickeylen,
    const char *aesencryptprivatekeystr,
    const unsigned long aesencryptprivatekeylen,
    const char *selfencryptionkeystr,
    const unsigned long selfencryptionkeylen)
{
    int ret = 1;

    unsigned char iv[ATCHOPS_IV_BUFFER_SIZE];
    memset(iv, 0, sizeof(unsigned char) * ATCHOPS_IV_BUFFER_SIZE);

    const unsigned long recvlen = 32768;
    unsigned char *recv = (unsigned char *)malloc(sizeof(unsigned char) * recvlen);
    unsigned long olen = 0;

    // 1. decrypt *.atKeys and populate atkeys struct

    // 1a. self encryption key
    ret = atclient_atstr_set(&(atkeys->selfencryptionkeystr), selfencryptionkeystr, selfencryptionkeylen);
    if(ret != 0)
    {
        atclient_atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atclient_atstr_set: %d | failed to set selfencryptionkeystr\n", ret);
        goto exit;
    }

    // 1b. pkam public key
    ret = atchops_aesctr_decrypt(
        atkeys->selfencryptionkeystr.str, atkeys->selfencryptionkeystr.olen, ATCHOPS_AES_256, iv,
        aespkampublickeystr, aespkampublickeylen,
        (unsigned char *) atkeys->pkampublickeystr.str, atkeys->pkampublickeystr.len, &(atkeys->pkampublickeystr.olen));
    if (ret != 0)
    {
        atclient_atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atchops_aesctr_decrypt: %d | failed to decrypt pkam public key\n", ret);
        goto exit;
    }
    memset(iv, 0, sizeof(unsigned char) * ATCHOPS_IV_BUFFER_SIZE);

    // 1c. pkam private key
    ret = atchops_aesctr_decrypt(
        atkeys->selfencryptionkeystr.str, atkeys->selfencryptionkeystr.olen, ATCHOPS_AES_256, iv,
        aespkamprivatekeystr, aespkamprivatekeylen,
        (unsigned char *) atkeys->pkamprivatekeystr.str, atkeys->pkamprivatekeystr.len, &(atkeys->pkamprivatekeystr.olen));
    if (ret != 0)
    {
        atclient_atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atchops_aesctr_decrypt: %d | failed to decrypt pkam private key\n", ret);
        goto exit;
    }
    memset(iv, 0, sizeof(unsigned char) * ATCHOPS_IV_BUFFER_SIZE);

    // 1d. encrypt public key
    ret = atchops_aesctr_decrypt(
        atkeys->selfencryptionkeystr.str, atkeys->selfencryptionkeystr.olen, ATCHOPS_AES_256, iv,
        aesencryptpublickeystr, aesencryptpublickeylen,
        (unsigned char *) atkeys->encryptpublickeystr.str, atkeys->encryptpublickeystr.len, &(atkeys->encryptpublickeystr.olen));
    if (ret != 0)
    {
        atclient_atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atchops_aesctr_decrypt: %d | failed to decrypt encrypt public key\n", ret);
        goto exit;
    }
    memset(iv, 0, sizeof(unsigned char) * ATCHOPS_IV_BUFFER_SIZE);

    // 1e. encrypt private key
    ret = atchops_aesctr_decrypt(
        atkeys->selfencryptionkeystr.str, atkeys->selfencryptionkeystr.olen, ATCHOPS_AES_256, iv,
        aesencryptprivatekeystr, aesencryptprivatekeylen,
        (unsigned char *) atkeys->encryptprivatekeystr.str, atkeys->encryptprivatekeystr.len, &(atkeys->encryptprivatekeystr.olen));
    if (ret != 0)
    {
        atclient_atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atchops_aesctr_decrypt: %d | failed to decrypt encrypt private key\n", ret);
        goto exit;
    }

    // 2. populate rsa structs in atkeys struct (4 keys)

    // 2a. pkam public key
    ret = atchops_rsakey_populate_publickey(&(atkeys->pkampublickey), atkeys->pkampublickeystr.str, atkeys->pkampublickeystr.olen);
    if(ret != 0)
    {
        atclient_atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atchops_rsakey_populate_publickey: %d | failed to populate pkam public key\n", ret);
        goto exit;
    }

    ret = atchops_rsakey_populate_privatekey(&(atkeys->pkamprivatekey), atkeys->pkamprivatekeystr.str, atkeys->pkamprivatekeystr.olen);
    if(ret != 0)
    {
        atclient_atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atchops_rsakey_populate_privatekey: %d | failed to populate pkam private key\n", ret);
        goto exit;
    }

    ret = atchops_rsakey_populate_privatekey(&(atkeys->encryptprivatekey), atkeys->encryptprivatekeystr.str, atkeys->encryptprivatekeystr.olen);
    if(ret != 0)
    {
        atclient_atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atchops_rsakey_populate_privatekey: %d | failed to populate encrypt private key\n", ret);
        goto exit;
    }

    ret = atchops_rsakey_populate_publickey(&(atkeys->encryptpublickey), atkeys->encryptpublickeystr.str, atkeys->encryptpublickeystr.olen);
    if(ret != 0)
    {
        atclient_atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atchops_rsakey_populate_publickey: %d | failed to populate encrypt public key\n", ret);
        goto exit;
    }

    goto exit;

exit:
{
    free(recv);
    return ret;
}
}

int atclient_atkeys_populate_from_atkeysfile(atclient_atkeys *atkeys, atclient_atkeysfile atkeysfile)
{
    int ret = 1;

    ret = atclient_atkeys_populate_from_strings(atkeys,
        atkeysfile.aespkampublickeystr.str, atkeysfile.aespkampublickeystr.olen,
        atkeysfile.aespkamprivatekeystr.str, atkeysfile.aespkamprivatekeystr.olen,
        atkeysfile.aesencryptpublickeystr.str, atkeysfile.aesencryptpublickeystr.olen,
        atkeysfile.aesencryptprivatekeystr.str, atkeysfile.aesencryptprivatekeystr.olen,
        atkeysfile.selfencryptionkeystr.str, atkeysfile.selfencryptionkeystr.olen);
    if(ret != 0)
    {
        atclient_atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atclient_atkeys_populate_from_strings: %d | failed to populate from strings\n", ret);
        goto exit;
    }

    goto exit;

exit:
{
    return ret;
}
}

int atclient_atkeys_populate_from_path(atclient_atkeys *atkeys, const char *path)
{
    int ret = 1;

    atclient_atkeysfile atkeysfile;
    atclient_atkeysfile_init(&atkeysfile);

    ret = atclient_atkeysfile_read(&atkeysfile, path);
    if (ret != 0)
    {
        atclient_atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atclient_atkeysfile_read: %d | failed to read file at path: %s\n", ret, path);
        goto exit;
    }

    ret = atclient_atkeys_populate_from_atkeysfile(atkeys, atkeysfile);
    if (ret != 0)
    {
        atclient_atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atclient_atkeys_populate_from_atkeysfile: %d | failed to decrypt & populate struct \n", ret);
        goto exit;
    }

    goto exit;
exit:
{
    atclient_atkeysfile_free(&atkeysfile);
    return ret;
}
}

int atclient_atkeys_populate_from_atstrs(atclient_atkeys *atkeys,
    const atclient_atstr aespkampublickeystr,
    const atclient_atstr aespkamprivatekeystr,
    const atclient_atstr aesencryptpublickeystr,
    const atclient_atstr aesencryptprivatekeystr,
    const atclient_atstr selfencryptionkeystr)
{
    int ret = 1;

    ret = atclient_atkeys_populate_from_strings(atkeys,
        aespkampublickeystr.str, aespkampublickeystr.olen,
        aespkamprivatekeystr.str, aespkamprivatekeystr.olen,
        aesencryptpublickeystr.str, aesencryptpublickeystr.olen,
        aesencryptprivatekeystr.str, aesencryptprivatekeystr.olen,
        selfencryptionkeystr.str, selfencryptionkeystr.olen);

    goto exit;

exit:
{
    return ret;
}
}

void atclient_atkeys_free(atclient_atkeys *atkeys)
{
    atclient_atstr_free(&(atkeys->pkampublickeystr));
    atchops_rsakey_publickey_free(&(atkeys->pkampublickey));
    atclient_atstr_free(&(atkeys->pkamprivatekeystr));
    atchops_rsakey_privatekey_free(&(atkeys->pkamprivatekey));
    atclient_atstr_free(&(atkeys->encryptpublickeystr));
    atchops_rsakey_publickey_free(&(atkeys->encryptpublickey));
    atclient_atstr_free(&(atkeys->encryptprivatekeystr));
    atchops_rsakey_privatekey_free(&(atkeys->encryptprivatekey));
    atclient_atstr_free(&(atkeys->selfencryptionkeystr));
}
