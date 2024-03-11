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
#define ATSIGN "@qt_thermostat"
#define ATKEYS_FILE_PATH "/Users/jeremytubongbanua/.atsign/keys/@qt_thermostat_key.atKeys"

int main()
{
    int ret = 1;

    atclient_atlogger_set_logging_level(ATLOGGER_LOGGING_LEVEL_DEBUG);

    const size_t valuelen = 4096;
    atclient_atstr value;
    atclient_atstr_init(&value, valuelen);

    atclient atclient;
    atclient_init(&atclient);

    atclient_connection root_connection;
    atclient_connection_init(&root_connection);
    atclient_connection_connect(&root_connection, "root.atsign.org", 64);

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

    if((ret = atclient_atkey_create_publickey(&atkey, "publickey", strlen("publickey"), "@jeremy_0", strlen("@jeremy_0"), NULL, 0)) != 0) {
        atclient_atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "Failed to create public key");
        goto exit;
    }

    if((ret = atclient_atkey_to_string(atkey, atkeystr.str, atkeystr.len, &atkeystr.olen)) != 0) {
        atclient_atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "Failed to convert to string");
        goto exit;
    }

    atclient_atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_DEBUG, "atkeystr.str (%lu): \"%.*s\"\n", atkeystr.olen, (int) atkeystr.olen, atkeystr.str);

    ret = atclient_get_publickey(&atclient, &root_connection, &atkey, value.str, value.len, &value.olen, true);
    if(ret != 0) {
        atclient_atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "Failed to get public key");
        goto exit;
    }

    atclient_atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_DEBUG, "Data: \"%.*s\"\n", (int) value.olen, value.str);

    char metadatajsonstr[4096];
    memset(metadatajsonstr, 0, 4096);
    size_t metadatstrolen = 0;

    ret = atclient_atkey_metadata_to_jsonstr(atkey.metadata, metadatajsonstr, 4096, &metadatstrolen);
    if(ret != 0) {
        atclient_atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "Failed to convert metadata to json string");
        goto exit;
    }

    atclient_atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_DEBUG, "Metadata: \"%.*s\"\n", (int) metadatstrolen, metadatajsonstr);

    ret = 0;
    goto exit;
exit: {
    atclient_atstr_free(&atkeystr);
    atclient_atkeys_free(&atkeys);
    atclient_atkey_free(&atkey);
    atclient_atsign_free(&atsign);
    atclient_free(&atclient);
    atclient_atstr_free(&value);
    return ret;
}
}
