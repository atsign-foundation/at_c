#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <atlogger/atlogger.h>
#include <atclient/metadata.h>
#include <atclient/atclient.h>
#include <atclient/atkey.h>
#include <atclient/atsign.h>
#include <atclient/constants.h>

// publickey

#define TAG "Debug"

// #define ATSIGN "@jeremy_0"
#define ATSIGN "@soccer0"
#define ATKEYS_FILE_PATH "/Users/jeremytubongbanua/.atsign/keys/@soccer0_key.atKeys"


#define ATKEY_KEY "test"
#define ATKEY_NAMESPACE "dart_playground"
#define ATKEY_VALUE "test value"
#define ATKEY_SHAREDWITH "@soccer99"

#define ROOT_HOST "root.atsign.org"
#define ROOT_PORT 64

int main()
{
    int ret = 1;

    atclient_atlogger_set_logging_level(ATLOGGER_LOGGING_LEVEL_DEBUG);

    const size_t valuesize = 2048;
    char value[valuesize];
    memset(value, 0, sizeof(char) * valuesize);
    size_t valueolen = 0;

    atclient atclient;
    atclient_init(&atclient);

    atclient_connection root_connection;
    atclient_connection_init(&root_connection);
    atclient_connection_connect(&root_connection, ROOT_HOST, ROOT_PORT);

    atclient_atsign atsign;
    atclient_atsign_init(&atsign, ATSIGN);

    atclient_atkey atkey;
    atclient_atkey_init(&atkey);

    atclient_atkeys atkeys;
    atclient_atkeys_init(&atkeys);
    atclient_atkeys_populate_from_path(&atkeys, ATKEYS_FILE_PATH);

    atclient_atstr atkeystr;
    atclient_atstr_init(&atkeystr, ATCLIENT_ATKEY_FULL_LEN);

    if((ret = atclient_pkam_authenticate(&atclient, &root_connection, atkeys, atsign.atsign, strlen(atsign.atsign))) != 0) {
        atclient_atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "Failed to authenticate");
        goto exit;
    }

    if((ret = atclient_atkey_create_sharedkey(&atkey, ATKEY_KEY, strlen(ATKEY_KEY), ATSIGN, strlen(ATSIGN), ATKEY_SHAREDWITH, strlen(ATKEY_SHAREDWITH), ATKEY_NAMESPACE, strlen(ATKEY_NAMESPACE))) != 0) {
        atclient_atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "Failed to create public key");
        goto exit;
    }

    atclient_atkey_metadata_set_ttl(&atkey.metadata, 60*1000*10); // 10 minutes

    if((ret = atclient_atkey_to_string(&atkey, atkeystr.str, atkeystr.len, &atkeystr.olen)) != 0) {
        atclient_atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "Failed to convert to string");
        goto exit;
    }

    atclient_atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_DEBUG, "Putting atkeystr.str (%lu): \"%.*s\"\n", atkeystr.olen, (int) atkeystr.olen, atkeystr.str);

    if((ret = atclient_put(&atclient, &root_connection, &atkey, ATKEY_VALUE, strlen(ATKEY_VALUE), NULL) != 0)) {
        atclient_atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "Failed to put public key");
        goto exit;
    }

    atclient_atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_DEBUG, "Done put.\n");

    ret = 0;
    goto exit;
exit: {
    atclient_atstr_free(&atkeystr);
    atclient_atkeys_free(&atkeys);
    atclient_atkey_free(&atkey);
    atclient_atsign_free(&atsign);
    atclient_free(&atclient);
    atclient_connection_free(&root_connection);
    return ret;
}
}