#include "atlogger/atlogger.h"
#include "atclient/metadata.h"

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

static int test_atkey_metadata_to_string() {
    int ret = 1;

    atclient_atkey_metadata metadata;
    atclient_atkey_metadata_init(&metadata);

    ret = 0;
    goto exit;
exit: {
    return ret;
}
}

int main() {
    int ret = 1;

    atclient_atkey_metadata metadata;
    atclient_atkey_metadata_init(&metadata);

    ret = 0;
    goto exit;
exit: {
    return ret;
}
}