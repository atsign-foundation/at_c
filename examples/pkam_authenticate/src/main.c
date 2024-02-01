#include <stdio.h>
#include <atclient/atclient.h>
#include <atclient/atkeysfile.h>
#include <atclient/atlogger.h>

#define ROOT_HOST "root.atsign.org"
#define ROOT_PORT 64

#define ATKEYSFILE_PATH "/Users/jeremytubongbanua/.atsign/keys/@smoothalligator_key.atKeys"
#define ATSIGN "@smoothalligator"

#define TAG "pkam_authenticate"

int main(int argc, char **argv)
{
    int ret = 1;

    atlogger_set_logging_level(ATLOGGER_LOGGING_LEVEL_INFO);

    // 1. init atkeys

    // 1a. read `atkeysfile` struct
    atclient_atkeysfile atkeysfile;
    atclient_atkeysfile_init(&atkeysfile);
    ret = atclient_atkeysfile_read(&atkeysfile, ATKEYSFILE_PATH);
    // printf("atkeysfile_read_code: %d\n", ret);
    if (ret != 0)
    {
        goto exit;
    }
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_INFO, "atclient_atkeys_file_read: %d\n", ret);

    // 1b. populate `atkeys` struct
    atclient_atkeys atkeys;
    atclient_atkeys_init(&atkeys);
    ret = atclient_atkeys_populate_from_atkeysfile(&atkeys, atkeysfile);
    // printf("atkeys_populate_code: %d\n", ret);
    if (ret != 0)
    {
        goto exit;
    }
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_INFO, "atclient_atkeys_populate_from_atkeysfile: %d\n", ret);

    // 2. pkam auth
    atclient atclient;
    atclient_init(&atclient);
    ret = atclient_init_root_connection(&atclient, ROOT_HOST, ROOT_PORT);
    // printf("atclient_init_root_connection_code: %d\n", ret);
    if (ret != 0)
    {
        goto exit;
    }

    ret = atclient_pkam_authenticate(&atclient, atkeys, ATSIGN, strlen(ATSIGN));
    // printf("atclient_pkam_authenticate_code: %d\n", ret);
    if (ret != 0)
    {
        goto exit;
    }

    goto exit;

exit:
{
    atclient_atkeysfile_free(&atkeysfile);
    atclient_atkeys_free(&atkeys);
    atclient_free(&atclient);
    return 0;
}
}