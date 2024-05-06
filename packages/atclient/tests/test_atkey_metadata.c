#include "atclient/metadata.h"
#include "atlogger/atlogger.h"
#include <string.h>
#include <stddef.h>

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
#define TEST_ATKEY_METADATA_FROM_JSONSTR                                                                               \
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

  ret = atclient_atkey_metadata_from_jsonstr(&metadata, TEST_ATKEY_METADATA_FROM_JSONSTR,
                                             strlen(TEST_ATKEY_METADATA_FROM_JSONSTR));
  if (ret != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atclient_atkey_metadata_from_jsonstr failed");
    goto exit;
  }

  if (strncmp(metadata.createdby.atsign, "@qt_thermostat", strlen("@qt_thermostat")) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "metadata.createdby.str != @qt_thermostat: %s",
                          metadata.createdby.atsign);
    ret = 1;
    goto exit;
  }

  if (strncmp(metadata.updatedby.atsign, "@qt_thermostat", strlen("@qt_thermostat")) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "metadata.updatedby.atsign != @qt_thermostat: %s",
                          metadata.updatedby.atsign);
    ret = 1;
    goto exit;
  }

  if (metadata.createdat.len <= 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "metadata.createdat.len <= 0: %lu",
                          metadata.createdat.len);
    ret = 1;
    goto exit;
  }

  if (strncmp(metadata.createdat.str, "2024-02-17 19:54:12.037Z", strlen("2024-02-17 19:54:12.037Z")) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "metadata.createdat.str != 2024-02-17 19:54:12.037Z: %s",
                          metadata.createdat.str);
    ret = 1;
    goto exit;
  }

  if (metadata.updatedat.len <= 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "metadata.updatedat.len <= 0: %lu",
                          metadata.updatedat.len);
    ret = 1;
    goto exit;
  }

  if (strncmp(metadata.updatedat.str, "2024-02-17 19:54:12.037Z", strlen("2024-02-17 19:54:12.037Z")) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "metadata.updatedat.str != 2024-02-17 19:54:12.037Z: %s",
                          metadata.updatedat.str);
    ret = 1;
    goto exit;
  }

  if (metadata.expiresat.len <= 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "metadata.expiresat.len <= 0: %lu",
                          metadata.expiresat.len);
    ret = 1;
    goto exit;
  }

  if (strncmp(metadata.expiresat.str, "2024-02-17 19:55:38.437Z", strlen("2024-02-17 19:55:38.437Z")) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "metadata.expiresat.str != 2024-02-17 19:55:38.437Z: %s",
                          metadata.expiresat.str);
    ret = 1;
    goto exit;
  }

  if (metadata.status.len != strlen("active")) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "metadata.status.len != strlen(active): %lu",
                          metadata.status.len);
    ret = 1;
    goto exit;
  }

  if (strncmp(metadata.status.str, "active", strlen("active")) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "metadata.status.str != active: %s", metadata.status.str);
    ret = 1;
    goto exit;
  }

  if (metadata.version != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "metadata.version != 0: %d", metadata.version);
    ret = 1;
    goto exit;
  }

  if (metadata.ttl != 86400) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "metadata.ttl != 86400: %ld", metadata.ttl);
    ret = 1;
    goto exit;
  }

  if (metadata.isbinary != false) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "metadata.isbinary != false: %d", metadata.isbinary);
    ret = 1;
    goto exit;
  }

  if (metadata.isencrypted != false) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "metadata.isencrypted != false: %d", metadata.isencrypted);
    ret = 1;
    goto exit;
  }

  if (metadata.iscached != false) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "metadata.iscached != false: %d", metadata.iscached);
    ret = 1;
    goto exit;
  }

  if (metadata.availableat.len != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "metadata.availableat.len != 0: %lu",
                          metadata.availableat.len);
    ret = 1;
    goto exit;
  }

  if (metadata.refreshat.len != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "metadata.refreshat.len != 0: %lu",
                          metadata.refreshat.len);
    ret = 1;
    goto exit;
  }

  if (metadata.datasignature.len != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "metadata.datasignature.len != 0: %lu",
                          metadata.datasignature.len);
    ret = 1;
    goto exit;
  }

  if (metadata.sharedkeystatus.len != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "metadata.sharedkeystatus.len != 0: %lu",
                          metadata.sharedkeystatus.len);
    ret = 1;
    goto exit;
  }

  if (metadata.sharedkeyenc.len != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "metadata.sharedkeyenc.len != 0: %lu",
                          metadata.sharedkeyenc.len);
    ret = 1;
    goto exit;
  }

  if (metadata.pubkeyhash.len != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "metadata.pubkeyhash.len != 0: %lu",
                          metadata.pubkeyhash.len);
    ret = 1;
    goto exit;
  }

  if (metadata.pubkeyalgo.len != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "metadata.pubkeyalgo.len != 0: %lu",
                          metadata.pubkeyalgo.len);
    ret = 1;
    goto exit;
  }

  if (metadata.encoding.len != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "metadata.encoding.len != 0: %lu",
                          metadata.encoding.len);
    ret = 1;
    goto exit;
  }

  if (metadata.enckeyname.len != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "metadata.enckeyname.len != 0: %lu",
                          metadata.enckeyname.len);
    ret = 1;
    goto exit;
  }

  if (metadata.encalgo.len != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "metadata.encalgo.len != 0: %lu", metadata.encalgo.len);
    ret = 1;
    goto exit;
  }

  if (metadata.ivnonce.len != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "metadata.ivnonce.len != 0: %lu", metadata.ivnonce.len);
    ret = 1;
    goto exit;
  }

  if (metadata.skeenckeyname.len != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "metadata.skeenckeyname.len != 0: %lu",
                          metadata.skeenckeyname.len);
    ret = 1;
    goto exit;
  }

  if (metadata.skeencalgo.len != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "metadata.skeencalgo.len != 0: %lu",
                          metadata.skeencalgo.len);
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

  const size_t protocolfragmentsize = 1024;
  char protocolfragment[protocolfragmentsize];
  memset(protocolfragment, 0, sizeof(char) * protocolfragmentsize);
  size_t protocolfragmentlen = 0;

  ret =
      atclient_atkey_metadata_to_protocol_str(&metadata, protocolfragment, protocolfragmentsize, &protocolfragmentlen);
  if (ret != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atclient_atkey_metadata_to_protocolstr failed");
    goto exit;
  }

  if (strlen(protocolfragment) != protocolfragmentlen) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR,
                          "strlen(protocolfragment) != protocolfragmentlen: %lu != %lu", strlen(protocolfragment),
                          protocolfragmentlen);
    ret = 1;
    goto exit;
  }

  if (protocolfragmentlen != expectedlen) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "protocolfragmentlen != expectedlen: %lu != %lu",
                          protocolfragmentlen, expectedlen);
    ret = 1;
    goto exit;
  }

  if (strncmp(protocolfragment, expected, expectedlen) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR,
                          "strncmp(protocolfragment, expected, expectedlen) != 0: %s != %s", protocolfragment,
                          expected);
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

  const size_t jsonstrsize = 4096;
  char jsonstr[jsonstrsize];
  memset(jsonstr, 0, sizeof(char) * jsonstrsize);
  size_t jsonstrlen = 0;

  ret = atclient_atkey_metadata_from_jsonstr(&metadata, TEST_ATKEY_METADATA_FROM_JSONSTR,
                                             strlen(TEST_ATKEY_METADATA_FROM_JSONSTR));
  if (ret != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atclient_atkey_metadata_from_jsonstr failed");
    goto exit;
  }

  ret = atclient_atkey_metadata_to_jsonstr(&metadata, jsonstr, jsonstrsize, &jsonstrlen);
  if (ret != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atclient_atkey_metadata_to_jsonstr failed");
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

  atlogger_set_logging_level(ATLOGGER_LOGGING_LEVEL_ERROR);

  if ((ret = test_atkey_metadata_from_jsonstr()) != 0) {
    goto exit;
  }

  if ((ret = test_atkey_metadata_to_jsonstr()) != 0) {
    goto exit;
  }

  if ((ret = test_atkey_metadata_to_protocolstr()) != 0) {
    goto exit;
  }

  ret = 0;
  goto exit;
exit: { return ret; }
}
