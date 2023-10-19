#include <stdio.h>
#include <atclient/atclient.h>
#include <atclient/atkeysfile.h>

#define ROOT_HOST "root.atsign.org"
#define ROOT_PORT 64

#define ATKEYSFILE_PATH "/Users/jeremytubongbanua/.atsign/keys/@smoothalligator_key.atKeys"
#define ATSIGN "@smoothalligator"

int main(int argc, char **argv)
{
    // 1. init atkeys

    // 1a. read `atkeysfile` struct
    atclient_atkeysfile atkeysfile;
    atclient_atkeysfile_init(&atkeysfile);
    int atkeys_read_code = atclient_atkeysfile_read(&atkeysfile, ATKEYSFILE_PATH);
    printf("atkeysfile_read_success: %d\n", atkeys_read_code);

    // 1b. populate `atkeys` struct
    atclient_atkeys atkeys;
    atclient_atkeys_init(&atkeys);
    int atkeys_populate_code = atclient_atkeys_populate(&atkeys, atkeysfile);
    printf("atkeys_populate_code: %d\n", atkeys_populate_code);

    // 2. pkam auth
    atclient_ctx atclient;
    atclient_init(&atclient);
    int root_connection_code = atclient_init_root_connection(&atclient, ROOT_HOST, ROOT_PORT);
    printf("root_connection_code: %d\n", root_connection_code);
    int pkam_authentication_code = atclient_pkam_authenticate(&atclient, atkeys, ATSIGN);
    printf("pkam_authentication_code: %d\n", pkam_authentication_code);

    goto exit;

exit:
{
    atclient_free(&atclient);
    atclient_atkeysfile_free(&atkeysfile);
    atclient_atkeys_free(&atkeys);
    return 0;
}
}