
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <atclient/atkeysfile.h>
#include <atclient/atkeys.h>

int main(int argc, char **argv)
{
    int ret = 1;
    const char *atkeysfile_path = "/Users/jeremytubongbanua/.atsign/keys/@smoothalligator_key.atKeys";
    atclient_atkeysfile atkeysfile;
    atclient_atkeysfile_init(&atkeysfile);
    ret = atclient_atkeysfile_read(&atkeysfile, atkeysfile_path);
    printf("atclient_atkeysfile_read: %d\n", ret);
    if (ret != 0)
    {
        goto exit;
    }
    // printf("aes_pkam_public_key: %lu | %s\n", atkeysfile.aes_pkam_public_key_olen, atkeysfile.aes_pkam_public_key);
    // printf("aes_pkam_private_key: %lu | %s\n", atkeysfile.aes_pkam_private_key_olen, atkeysfile.aes_pkam_private_key);
    // printf("aes_encrypt_public_key: %lu | %s\n", atkeysfile.aes_encrypt_public_key_olen, atkeysfile.aes_encrypt_public_key);
    // printf("aes_encrypt_private_key: %lu | %s\n", atkeysfile.aes_encrypt_private_key_olen, atkeysfile.aes_encrypt_private_key);
    // printf("selfencryptionkeystr: %lu | %s\n", atkeysfile.self_encryption_key_olen, atkeysfile.selfencryptionkeystr);

    atclient_atkeys atkeys;
    atclient_atkeys_init(&atkeys);
    ret = atclient_atkeys_populate(&atkeys, atkeysfile);
    printf("atclient_atkeys_populate: %d\n", ret);
    if (ret != 0)
    {
        goto exit;
    }

    // printf("pkam private key (decrypted): %lu | %s\n", atkeys.pkamprivatekeyolen, atkeys.pkamprivatekeystr);
    // printf("pkam public key  (decrypted): %lu | %s\n", atkeys.pkampublickeyolen, atkeys.pkampublickeystr);
    // printf("encrypt private key (decrypted): %lu | %s\n", atkeys.encryptprivatekeyolen, atkeys.encryptprivatekeystr);
    // printf("encrypt public key (decrypted): %lu | %s\n", atkeys.encryptpublickeyolen, atkeys.encryptpublickeystr);
    // printf("self encryption key: %lu | %s\n", atkeys.selfencryptionkeyolen, atkeys.selfencryptionkeystr);

exit:
{
    return ret;
}
}