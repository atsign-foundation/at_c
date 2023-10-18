#include <stdio.h>
#include <atclient/atclient.h>
#include <atclient/atkeys_filereader.h>

#define ROOT_HOST "root.atsign.org"
#define ROOT_PORT 64

int main(int argc, char **argv)
{
    atclient_ctx atclient;
    atclient_init(&atclient);
    int root_connection_success = atclient_init_root_connection(&atclient, ROOT_HOST, ROOT_PORT);
    printf("root_connection_success: %d\n", root_connection_success);

    // 1. init atkeys
    atclient_atkeysfile atkeysfile;
    atclient_atkeysfile_init(&atkeysfile);
    int atkeys_read_success = atclient_atkeysfile_read("/Users/jeremytubongbanua/.atsign/keys/@jeremy_0_key.atKeys", &atkeysfile);
    printf("atkeys_read_success: %d\n", atkeys_read_success);

    // 2. pkam auth
    int pkam_authentication_success = atclient_pkam_authenticate(&atclient, "@jeremy_0", &atkeysfile);
    printf("pkam_authentication_success: %d\n", pkam_authentication_success);

    return 0;
}