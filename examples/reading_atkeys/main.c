
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
    // printf("self_encryption_key: %lu | %s\n", atkeysfile.self_encryption_key_olen, atkeysfile.self_encryption_key);

    atclient_atkeys atkeys;
    ret = atclient_atkeys_populate(&atkeys, &atkeysfile);
    printf("atclient_atkeys_populate: %d\n", ret);
    if (ret != 0)
    {
        goto exit;
    }

    printf("aes_pkam_private_key: %lu | %s\n", atkeys.pkam_private_key_olen, atkeys.pkam_private_key);
    printf("aes_pkam_public_key: %lu | %s\n", atkeys.pkam_public_key_olen, atkeys.pkam_public_key);
    printf("aes_encrypt_private_key: %lu | %s\n", atkeys.encrypt_private_key_olen, atkeys.encrypt_private_key);
    printf("aes_encrypt_public_key: %lu | %s\n", atkeys.encrypt_public_key_olen, atkeys.encrypt_public_key);
    printf("self_encryption_key: %lu | %s\n", atkeys.self_encryption_key_olen, atkeys.self_encryption_key);

exit:
{
    return ret;
}
}