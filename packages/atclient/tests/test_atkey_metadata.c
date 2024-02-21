#include "atlogger/atlogger.h"
#include "atclient/metadata.h"
#include <string.h>

// example:
// "metaData":{
//  "createdBy":"@qt_thermostat",
//  "updatedBy":"@qt_thermostat",
//  "createdAt":"2024-02-17 19:54:12.037Z",
//  "updatedAt":"2024-02-17 19:54:12.037Z",
//  "expiresAt":"2024-02-17 19:55:38.437Z",
//  "status":"active",
//  "version":0,
//  "ttl":86400,
//  "isBinary":false,
//  "isEncrypted":false
// }

#define TAG "test_atkey_metadata"

// createdBy, updatedBy, status, and version are not read
#define TEST_ATKEY_METADATA_FROM_JSONSTR \
    "{                                              \
        \"createdBy\":\"@qt_thermostat\",           \
        \"updatedBy\":\"@qt_thermostat\",           \
        \"createdAt\":\"2024-02-17 19:54:12.037Z\", \
        \"updatedAt\":\"2024-02-17 19:54:12.037Z\", \
        \"expiresAt\":\"2024-02-17 19:55:38.437Z\", \
        \"status\":\"active\",                      \
        \"version\":0,                              \
        \"ttl\":86400,                              \
        \"isBinary\":false,                         \
        \"isEncrypted\":false                       \
    }"

static int test_atkey_metadata_from_jsonstr() {
    int ret = 1;

    atclient_atkey_metadata metadata;
    atclient_atkey_metadata_init(&metadata);

    ret = atclient_atkey_metadata_from_jsonstr(&metadata, TEST_ATKEY_METADATA_FROM_JSONSTR, strlen(TEST_ATKEY_METADATA_FROM_JSONSTR));
    if(ret != 0) {
        atclient_atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atclient_atkey_metadata_from_jsonstr failed");
        goto exit;
    }

    if(metadata.createdby.olen != strlen("@qt_thermostat")) {
        atclient_atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "metadata.createdby.olen != strlen(@qt_thermostat): %lu", metadata.createdby.olen);
        ret = 1;
        goto exit;
    }

    if(strncmp(metadata.createdby.str, "@qt_thermostat", strlen("@qt_thermostat")) != 0) {
        atclient_atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "metadata.createdby.str != @qt_thermostat: %s", metadata.createdby.str);
        ret = 1;
        goto exit;
    }

    if(metadata.updatedby.olen != strlen("@qt_thermostat")) {
        atclient_atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "metadata.updatedby.olen != strlen(@qt_thermostat): %lu", metadata.updatedby.olen);
        ret = 1;
        goto exit;
    }

    if(strncmp(metadata.updatedby.str, "@qt_thermostat", strlen("@qt_thermostat")) != 0) {
        atclient_atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "metadata.updatedby.str != @qt_thermostat: %s", metadata.updatedby.str);
        ret = 1;
        goto exit;
    }

    if(metadata.createdat.olen <= 0) {
        atclient_atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "metadata.createdat.olen <= 0: %lu", metadata.createdat.olen);
        ret = 1;
        goto exit;
    }

    if(strncmp(metadata.createdat.str, "2024-02-17 19:54:12.037Z", strlen("2024-02-17 19:54:12.037Z")) != 0) {
        atclient_atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "metadata.createdat.str != 2024-02-17 19:54:12.037Z: %s", metadata.createdat.str);
        ret = 1;
        goto exit;
    }

    if(metadata.updatedat.olen <= 0) {
        atclient_atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "metadata.updatedat.olen <= 0: %lu", metadata.updatedat.olen);
        ret = 1;
        goto exit;
    }

    if(strncmp(metadata.updatedat.str, "2024-02-17 19:54:12.037Z", strlen("2024-02-17 19:54:12.037Z")) != 0) {
        atclient_atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "metadata.updatedat.str != 2024-02-17 19:54:12.037Z: %s", metadata.updatedat.str);
        ret = 1;
        goto exit;
    }

    if(metadata.expiresat.olen <= 0) {
        atclient_atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "metadata.expiresat.olen <= 0: %lu", metadata.expiresat.olen);
        ret = 1;
        goto exit;
    }

    if(strncmp(metadata.expiresat.str, "2024-02-17 19:55:38.437Z", strlen("2024-02-17 19:55:38.437Z")) != 0) {
        atclient_atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "metadata.expiresat.str != 2024-02-17 19:55:38.437Z: %s", metadata.expiresat.str);
        ret = 1;
        goto exit;
    }

    if(metadata.status.olen != strlen("active")) {
        atclient_atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "metadata.status.olen != strlen(active): %lu", metadata.status.olen);
        ret = 1;
        goto exit;
    }

    if(strncmp(metadata.status.str, "active", strlen("active")) != 0) {
        atclient_atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "metadata.status.str != active: %s", metadata.status.str);
        ret = 1;
        goto exit;
    }

    if(metadata.version != 0) {
        atclient_atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "metadata.version != 0: %d", metadata.version);
        ret = 1;
        goto exit;
    }

    if(metadata.ttl != 86400) {
        atclient_atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "metadata.ttl != 86400: %ld", metadata.ttl);
        ret = 1;
        goto exit;
    }

    if(metadata.isbinary != false) {
        atclient_atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "metadata.isbinary != false: %d", metadata.isbinary);
        ret = 1;
        goto exit;
    }

    if(metadata.isencrypted != false) {
        atclient_atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "metadata.isencrypted != false: %d", metadata.isencrypted);
        ret = 1;
        goto exit;
    }

    if(metadata.iscached != false) {
        atclient_atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "metadata.iscached != false: %d", metadata.iscached);
        ret = 1;
        goto exit;
    }

    if(metadata.availableat.olen != 0) {
        atclient_atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "metadata.availableat.olen != 0: %lu", metadata.availableat.olen);
        ret = 1;
        goto exit;
    }

    if(metadata.refreshat.olen != 0) {
        atclient_atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "metadata.refreshat.olen != 0: %lu", metadata.refreshat.olen);
        ret = 1;
        goto exit;
    }

    if(metadata.datasignature.olen != 0) {
        atclient_atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "metadata.datasignature.olen != 0: %lu", metadata.datasignature.olen);
        ret = 1;
        goto exit;
    }

    if(metadata.sharedkeystatus.olen != 0) {
        atclient_atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "metadata.sharedkeystatus.olen != 0: %lu", metadata.sharedkeystatus.olen);
        ret = 1;
        goto exit;
    }

    if(metadata.sharedkeyenc.olen != 0) {
        atclient_atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "metadata.sharedkeyenc.olen != 0: %lu", metadata.sharedkeyenc.olen);
        ret = 1;
        goto exit;
    }

    if(metadata.pubkeyhash.olen != 0) {
        atclient_atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "metadata.pubkeyhash.olen != 0: %lu", metadata.pubkeyhash.olen);
        ret = 1;
        goto exit;
    }

    if(metadata.pubkeyalgo.olen != 0) {
        atclient_atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "metadata.pubkeyalgo.olen != 0: %lu", metadata.pubkeyalgo.olen);
        ret = 1;
        goto exit;
    }

    if(metadata.encoding.olen != 0) {
        atclient_atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "metadata.encoding.olen != 0: %lu", metadata.encoding.olen);
        ret = 1;
        goto exit;
    }

    if(metadata.enckeyname.olen != 0) {
        atclient_atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "metadata.enckeyname.olen != 0: %lu", metadata.enckeyname.olen);
        ret = 1;
        goto exit;
    }

    if(metadata.encalgo.olen != 0) {
        atclient_atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "metadata.encalgo.olen != 0: %lu", metadata.encalgo.olen);
        ret = 1;
        goto exit;
    }

    if(metadata.ivnonce.olen != 0) {
        atclient_atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "metadata.ivnonce.olen != 0: %lu", metadata.ivnonce.olen);
        ret = 1;
        goto exit;
    }

    if(metadata.skeenckeyname.olen != 0) {
        atclient_atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "metadata.skeenckeyname.olen != 0: %lu", metadata.skeenckeyname.olen);
        ret = 1;
        goto exit;
    }

    if(metadata.skeencalgo.olen != 0) {
        atclient_atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "metadata.skeencalgo.olen != 0: %lu", metadata.skeencalgo.olen);
        ret = 1;
        goto exit;
    }

    ret = 0;
    goto exit;
exit: {
    atclient_atkey_metadata_free(&metadata);
    return ret;
}
}

static int test_atkey_metadata_to_protocolstr() {
    int ret = 1;

    const char *expected = ":ttr:-1:isBinary:true:isEncrypted:true:ivNonce:abcdefghijk";
    const size_t expectedlen = strlen(expected);

    atclient_atkey_metadata metadata;
    atclient_atkey_metadata_init(&metadata);

    atclient_atkey_metadata_set_ttr(&metadata, -1);
    atclient_atkey_metadata_set_isbinary(&metadata, true);
    atclient_atkey_metadata_set_isencrypted(&metadata, true);
    atclient_atkey_metadata_set_iscached(&metadata, true);
    atclient_atkey_metadata_set_ivnonce(&metadata, "abcdefghijk", strlen("abcdefghijk"));

    const size_t protocolfragmentlen = 1024;
    char protocolfragment[protocolfragmentlen];
    memset(protocolfragment, 0, sizeof(char) * protocolfragmentlen);
    size_t protocolfragmentolen = 0;

    ret = atclient_atkey_metadata_to_protocolstr(metadata, protocolfragment, protocolfragmentlen, &protocolfragmentolen);
    if(ret != 0) {
        atclient_atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atclient_atkey_metadata_to_protocolstr failed");
        goto exit;
    }


    if(strlen(protocolfragment) != protocolfragmentolen) {
        atclient_atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "strlen(protocolfragment) != protocolfragmentolen: %lu != %lu", strlen(protocolfragment), protocolfragmentolen);
        ret = 1;
        goto exit;
    }

    if(protocolfragmentolen != expectedlen) {
        atclient_atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "protocolfragmentolen != expectedlen: %lu != %lu", protocolfragmentolen, expectedlen);
        ret = 1;
        goto exit;
    }

    if(strncmp(protocolfragment, expected, expectedlen) != 0) {
        atclient_atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "strncmp(protocolfragment, expected, expectedlen) != 0: %s != %s", protocolfragment, expected);
        ret = 1;
        goto exit;
    }

    ret = 0;
    goto exit;
exit: {
    atclient_atkey_metadata_free(&metadata);
    return ret;
}
}

static int test_atkey_metadata_to_jsonstr() {
    int ret = 1;

    atclient_atkey_metadata metadata;
    atclient_atkey_metadata_init(&metadata);

    ret = atclient_atkey_metadata_from_jsonstr(&metadata, TEST_ATKEY_METADATA_FROM_JSONSTR, strlen(TEST_ATKEY_METADATA_FROM_JSONSTR));
    if(ret != 0) {
        atclient_atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atclient_atkey_metadata_from_jsonstr failed");
        goto exit;
    }

    const size_t jsonstrlen = 4096;
    char jsonstr[jsonstrlen];
    memset(jsonstr, 0, sizeof(char) * jsonstrlen);
    size_t jsonstrlenout = 0;

    ret = atclient_atkey_metadata_to_jsonstr(metadata, jsonstr, jsonstrlen, &jsonstrlenout);
    if(ret != 0) {
        atclient_atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atclient_atkey_metadata_to_jsonstr failed");
        goto exit;
    }

    ret = 0;
    goto exit;
exit: {
    atclient_atkey_metadata_free(&metadata);
    return ret;
}
}

int main() {
    int ret = 1;

    atclient_atlogger_set_logging_level(ATLOGGER_LOGGING_LEVEL_ERROR);

    if((ret = test_atkey_metadata_from_jsonstr()) != 0) {
        goto exit;
    }

    if((ret = test_atkey_metadata_to_jsonstr()) != 0) {
        goto exit;
    }

    if((ret = test_atkey_metadata_to_protocolstr()) != 0) {
        goto exit;
    }

    ret = 0;
    goto exit;
exit: {
    return ret;
}
}