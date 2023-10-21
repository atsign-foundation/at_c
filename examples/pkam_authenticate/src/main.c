#include <stdio.h>
#include <atclient/atclient.h>
#include <atclient/atkeysfile.h>

#define ROOT_HOST "root.atsign.org"
#define ROOT_PORT 64

#define ATKEYSFILE_PATH "/Users/jeremytubongbanua/.atsign/keys/@smoothalligator_key.atKeys"
#define ATSIGN "@smoothalligator"

int main(int argc, char **argv)
{
    int ret = 1;
    // 1. init atkeys

    // 1a. read `atkeysfile` struct
    atclient_atkeysfile atkeysfile;
    atclient_atkeysfile_init(&atkeysfile);
    ret = atclient_atkeysfile_read(&atkeysfile, ATKEYSFILE_PATH);
    printf("atkeysfile_read_code: %d\n", ret);
    if (ret != 0)
    {
        goto exit;
    }

    // 1b. populate `atkeys` struct
    atclient_atkeys atkeys;
    atclient_atkeys_init(&atkeys);
    ret = atclient_atkeys_populate(&atkeys, atkeysfile);
    printf("atkeys_populate_code: %d\n", ret);
    if (ret != 0)
    {
        goto exit;
    }

    // 2. pkam auth
    atclient_ctx atclient;
    atclient_init(&atclient);
    ret = atclient_init_root_connection(&atclient, ROOT_HOST, ROOT_PORT);
    printf("atclient_init_root_connection_code: %d\n", ret);
    if (ret != 0)
    {
        goto exit;
    }

    ret = atclient_pkam_authenticate(&atclient, atkeys, ATSIGN);
    printf("atclient_pkam_authenticate_code: %d\n", ret);
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