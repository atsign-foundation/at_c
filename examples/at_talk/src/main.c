#include <stdio.h>
#include <stdlib.h>
#include <atclient/atclient.h>
#include <atclient/atsign.h>
#include <atclient/atkeysfile.h>
#include <atclient/atlogger.h>

#define ROOT_HOST "root.atsign.org"
#define ROOT_PORT 64

#define ATKEYSFILE_PATH "/home/realvarx/.atsign/keys/@arrogantcheetah_key.atKeys"
#define ATSIGN "@arrogantcheetah"

#define TAG "at_talk"

int main(int argc, char **argv)
{
    int ret = 1;

    atlogger_set_logging_level(ATLOGGER_LOGGING_LEVEL_INFO);

    atclient_ctx atclient;
    atclient_init(&atclient, ATSIGN);

    ret = atclient_init_root_connection(&atclient, ROOT_HOST, ROOT_PORT);
    if (ret != 0)
    {
        goto exit;
    }

    ret = atclient_pkam_authenticate(&atclient, atclient.atkeys, ATSIGN);
    if (ret != 0)
    {
        goto exit;
    }

    char *enc_key_shared_by_me = malloc(45);
    char *enc_key_shared_by_other = malloc(45);
    get_encryption_key_shared_by_me(&atclient, "secondaryjackal", enc_key_shared_by_me);
    get_encryption_key_shared_by_other(&atclient, "secondaryjackal", enc_key_shared_by_other);
    printf("enc_key_shared_by_me: %s\n", enc_key_shared_by_me);
    printf("enc_key_shared_by_other: %s\n", enc_key_shared_by_other);

    attalk_send(&atclient, atclient.atkeys, "arrogantcheetah", "secondaryjackal", enc_key_shared_by_me, "hello from at_c!");
    puts("Finished");
    goto exit;

exit:
{
    // atclient_atkeysfile_free(&atkeysfile);
    // atclient_atkeys_free(&atkeys);
    atclient_free(&atclient);
    return 0;
}
}