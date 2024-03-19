#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <atlogger/atlogger.h>
#include <atclient/metadata.h>
#include <atclient/constants.h>
#include <atclient/atclient.h>
#include <atclient/atkey.h>
#include <atclient/atsign.h>

#define TAG "noci_test_get_sharedkey"

#define ATSIGN "@expensiveferret"

#define ATKEYS_FILE_PATH "/home/realvarx/.atsign/keys/@expensiveferret_key.atKeys"

int main()
{
    // Disable buffering
    setbuf(stdout, NULL);
    setbuf(stderr, NULL);

    int ret = 1;

    atclient_atlogger_set_logging_level(ATLOGGER_LOGGING_LEVEL_DEBUG);

    const size_t valuelen = 1024;
    atclient_atstr value;
    atclient_atstr_init(&value, valuelen);

    atclient_connection root_conn;
    atclient_connection_init(&root_conn);
    atclient_connection_connect(&root_conn, "root.atsign.org", 64);

    atclient atclient;
    atclient_init(&atclient);

    atclient_atsign atsign;
    atclient_atsign_init(&atsign, ATSIGN);

    atclient_atkey atkey;
    atclient_atkey_init(&atkey);

    atclient_atkeys atkeys;
    atclient_atkeys_init(&atkeys);
    atclient_atkeys_populate_from_path(&atkeys, ATKEYS_FILE_PATH);

    atclient_atstr atkeystr;
    atclient_atstr_init(&atkeystr, ATCLIENT_ATKEY_FULL_LEN);

    if((ret = atclient_pkam_authenticate(&atclient, &root_conn, atkeys, atsign.atsign, strlen(atsign.atsign))) != 0) {
        atclient_atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "Failed to authenticate\n");
        goto exit;
    } else {
        atclient_atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_DEBUG, "Authenticated\n");
    }
    
    atclient.atkeys = atkeys;
    atclient.atsign = atsign;
    
    if((ret = atclient_atkey_create_sharedkey(&atkey, "test_sharedkey_001", strlen("test_sharedkey_001"), atsign.atsign, strlen(atsign.atsign), "@secondaryjackal", strlen("@secondaryjackal"), "dart_playground", strlen("dart_playground"))) != 0) {
        atclient_atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "Failed to create shared key\n");
        goto exit;
    } else {
        atclient_atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_DEBUG, "Created shared key\n");
    }

    if((ret = atclient_atkey_to_string(atkey, atkeystr.str, atkeystr.len, &atkeystr.olen)) != 0) {
        atclient_atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "Failed to convert to string\n");
        goto exit;
    }

    atclient_atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_DEBUG, "atkeystr.str (%lu): \"%.*s\"\n", atkeystr.olen, (int) atkeystr.olen, atkeystr.str);


    ret = atclient_get_sharedkey(&atclient, &atkey, value.str, value.len, &value.olen, NULL, false);
    if(ret != 0) {
        atclient_atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "Failed to get shared key");
        goto exit;
    }
    
    atclient_atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_DEBUG, "value.str (%lu): \"%.*s\"\n", value.olen, (int) value.olen, value.str);


    ret = 0;
    goto exit;
exit: {
    atclient_atstr_free(&value);
    atclient_atkey_free(&atkey);
    atclient_atkeys_free(&atkeys);
    atclient_atstr_free(&atkeystr);
    atclient_atsign_free(&atsign);
    atclient_free(&atclient);
    return ret;
}
}
