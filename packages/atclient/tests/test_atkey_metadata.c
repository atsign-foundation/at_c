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

#define TEST_ATKEY_METADATA_FROM_JSONSTR \
    "\"metadata\": { \
        \"createdBy\":\"@qt_thermostat\", \
        \"updatedBy\":\"@qt_thermostat\", \
        \"createdAt\":\"2024-02-17 19:54:12.037Z\", \
        \"updatedAt\":\"2024-02-17 19:54:12.037Z\", \
        \"expiresAt\":\"2024-02-17 19:55:38.437Z\", \
        \"status\":\"active\", \
        \"version\":0, \
        \"ttl\":86400, \
        \"isBinary\":false, \
        \"isEncrypted\":false \
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

    // if(metadata.createdat.olen <= 0) {
    //     atclient_atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "metadata.createdat.olen <= 0: %lu", metadata.createdat.olen);
    //     ret = 1;
    //     goto exit;
    // }

    // if(strncmp(metadata.createdat.str, "2024-02-17 19:54:12.037Z", strlen("2024-02-17 19:54:12.037Z")) != 0) {
    //     atclient_atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "metadata.createdat.str != 2024-02-17 19:54:12.037Z: %s", metadata.createdat.str);
    //     ret = 1;
    //     goto exit;
    // }

    // if(metadata.updatedat.olen <= 0) {
    //     atclient_atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "metadata.updatedat.olen <= 0: %lu", metadata.updatedat.olen);
    //     ret = 1;
    //     goto exit;
    // }

    // if(strncmp(metadata.updatedat.str, "2024-02-17 19:54:12.037Z", strlen("2024-02-17 19:54:12.037Z")) != 0) {
    //     atclient_atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "metadata.updatedat.str != 2024-02-17 19:54:12.037Z: %s", metadata.updatedat.str);
    //     ret = 1;
    //     goto exit;
    // }

    // if(metadata.expiresat.olen <= 0) {
    //     atclient_atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "metadata.expiresat.olen <= 0: %lu", metadata.expiresat.olen);
    //     ret = 1;
    //     goto exit;
    // }

    // if(strncmp(metadata.expiresat.str, "2024-02-17 19:55:38.437Z", strlen("2024-02-17 19:55:38.437Z")) != 0) {
    //     atclient_atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "metadata.expiresat.str != 2024-02-17 19:55:38.437Z: %s", metadata.expiresat.str);
    //     ret = 1;
    //     goto exit;
    // }

    ret = 0;
    goto exit;
exit: {
    atclient_atkey_metadata_free(&metadata);
    return ret;
}
}

static int test_atkey_metadata_to_protocolstr() {
    int ret = 1;

    atclient_atkey_metadata metadata;
    atclient_atkey_metadata_init(&metadata);

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