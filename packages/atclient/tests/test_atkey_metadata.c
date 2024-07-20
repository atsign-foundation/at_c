#include "atclient/metadata.h"
#include "atlogger/atlogger.h"
#include <stddef.h>
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

  if ((ret = atclient_atkey_metadata_from_jsonstr(&metadata, TEST_ATKEY_METADATA_FROM_JSONSTR,
                                                  strlen(TEST_ATKEY_METADATA_FROM_JSONSTR))) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atclient_atkey_metadata_from_jsonstr failed");
    goto exit;
  }

  if (!atclient_atkey_metadata_is_createdby_initialized(&metadata)) {
    ret = 1;
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atclient_atkey_metadata_is_createdby_initialized failed");
    goto exit;
  }

  if (strcmp(metadata.createdby, "@qt_thermostat") != 0) {
    ret = 1;
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "metadata.createdby != @qt_thermostat: %s", metadata.createdby);
    goto exit;
  }

  if (!atclient_atkey_metadata_is_updatedby_initialized(&metadata)) {
    ret = 1;
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atclient_atkey_metadata_is_updatedby_initialized failed");
    goto exit;
  }

  if (strcmp(metadata.updatedby, "@qt_thermostat") != 0) {
    ret = 1;
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "metadata.updatedby.atsign != @qt_thermostat: %s",
                 metadata.updatedby);
    goto exit;
  }

  if (!atclient_atkey_metadata_is_createdat_initialized(&metadata)) {
    ret = 1;
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atclient_atkey_metadata_is_createdat_initialized failed");
    goto exit;
  }

  if (strlen(metadata.createdat) <= 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "strlen(metadata.createdat) <= 0: %lu", strlen(metadata.createdat));
    ret = 1;
    goto exit;
  }

  if (!atclient_atkey_metadata_is_updatedat_initialized(&metadata)) {
    ret = 1;
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atclient_atkey_metadata_is_updatedat_initialized failed");
    goto exit;
  }

  if (strcmp(metadata.createdat, "2024-02-17 19:54:12.037Z") != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "metadata.createdat != 2024-02-17 19:54:12.037Z: %s",
                 metadata.createdat);
    ret = 1;
    goto exit;
  }

  if (!atclient_atkey_metadata_is_updatedat_initialized(&metadata)) {
    ret = 1;
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atclient_atkey_metadata_is_updatedat_initialized failed");
    goto exit;
  }

  if (strlen(metadata.updatedat) <= 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "strlen(metadata.updatedat) <= 0: %lu", strlen(metadata.updatedat));
    ret = 1;
    goto exit;
  }

  if (!atclient_atkey_metadata_is_updatedat_initialized(&metadata)) {
    ret = 1;
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atclient_atkey_metadata_is_updatedat_initialized failed");
    goto exit;
  }

  if (strcmp(metadata.updatedat, "2024-02-17 19:54:12.037Z") != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "metadata.updatedat != 2024-02-17 19:54:12.037Z: %s",
                 metadata.updatedat);
    ret = 1;
    goto exit;
  }

  if (!atclient_atkey_metadata_is_expiresat_initialized(&metadata)) {
    ret = 1;
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atclient_atkey_metadata_is_expiresat_initialized failed");
    goto exit;
  }

  if (strlen(metadata.expiresat) <= 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "strlen(metadata.expiresat) <= 0: %lu", strlen(metadata.expiresat));
    ret = 1;
    goto exit;
  }

  if (!atclient_atkey_metadata_is_status_initialized(&metadata)) {
    ret = 1;
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atclient_atkey_metadata_is_status_initialized failed");
    goto exit;
  }

  if (strcmp(metadata.expiresat, "2024-02-17 19:55:38.437Z") != 0) {
    ret = 1;
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "metadata.expiresat != 2024-02-17 19:55:38.437Z: %s",
                 metadata.expiresat);
    goto exit;
  }

  if (!atclient_atkey_metadata_is_status_initialized(&metadata)) {
    ret = 1;
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atclient_atkey_metadata_is_status_initialized failed");
    goto exit;
  }

  if (strlen(metadata.status) != strlen("active")) {
    ret = 1;
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "metadata.status != strlen(active): %lu", strlen(metadata.status));
    goto exit;
  }

  if (!atclient_atkey_metadata_is_version_initialized(&metadata)) {
    ret = 1;
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atclient_atkey_metadata_is_version_initialized failed");
    goto exit;
  }

  if (strcmp(metadata.status, "active") != 0) {
    ret = 1;
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "metadata.status != active: %s", metadata.status);
    goto exit;
  }

  if (!atclient_atkey_metadata_is_version_initialized(&metadata)) {
    ret = 1;
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atclient_atkey_metadata_is_version_initialized failed");
    goto exit;
  }

  if (metadata.version != 0) {
    ret = 1;
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "metadata.version != 0: %d", metadata.version);
    goto exit;
  }

  if (!atclient_atkey_metadata_is_ttl_initialized(&metadata)) {
    ret = 1;
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atclient_atkey_metadata_is_ttl_initialized failed");
    goto exit;
  }

  if (metadata.ttl != 86400) {
    ret = 1;
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "metadata.ttl != 86400: %ld", metadata.ttl);
    goto exit;
  }

  if (!atclient_atkey_metadata_is_isbinary_initialized(&metadata)) {
    ret = 1;
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atclient_atkey_metadata_isbinary_initialized failed");
    goto exit;
  }

  if (metadata.isbinary != false) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "metadata.isbinary != false: %d", metadata.isbinary);
    ret = 1;
    goto exit;
  }

  if (!atclient_atkey_metadata_is_isencrypted_initialized(&metadata)) {
    ret = 1;
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atclient_atkey_metadata_isencrypted_initialized failed");
    goto exit;
  }

  if (metadata.isencrypted != false) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "metadata.isencrypted != false: %d", metadata.isencrypted);
    ret = 1;
    goto exit;
  }

  if (!atclient_atkey_metadata_is_iscached_initialized(&metadata)) {
    ret = 1;
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atclient_atkey_metadata_iscached_initialized failed");
    goto exit;
  }

  if (metadata.iscached != false) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "metadata.iscached != false: %d", metadata.iscached);
    ret = 1;
    goto exit;
  }

  if (!atclient_atkey_metadata_is_availableat_initialized(&metadata)) {
    ret = 1;
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atclient_atkey_metadata_isavailableat_initialized failed");
    goto exit;
  }

  if (strlen(metadata.availableat) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "strlen(metadata.availableat) != 0: %lu",
                 strlen(metadata.availableat));
    ret = 1;
    goto exit;
  }

  if (strlen(metadata.refreshat) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "strlen(metadata.refreshat) != 0: %lu", strlen(metadata.refreshat));
    ret = 1;
    goto exit;
  }

  if (atclient_atkey_metadata_is_datasignature_initialized(&metadata)) {
    ret = 1;
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "datasignature is initialized when it should not be");
    goto exit;
  }

  if (strlen(metadata.datasignature) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "strlen(metadata.datasignature != 0: %lu",
                 strlen(metadata.datasignature));
    ret = 1;
    goto exit;
  }

  if (atclient_atkey_metadata_is_sharedkeystatus_initialized(&metadata)) {
    ret = 1;
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "sharedby is initialized when it should not be");
    goto exit;
  }

  if (strlen(metadata.sharedkeystatus) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "strlen(metadata.sharedkeystatus) != 0: %lu",
                 strlen(metadata.sharedkeystatus));
    ret = 1;
    goto exit;
  }

  if (atclient_atkey_metadata_is_sharedkeyenc_initialized(&metadata)) {
    ret = 1;
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "sharedkeyenc is initialized when it should not be");
    goto exit;
  }

  if (strlen(metadata.sharedkeyenc) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "strlen(metadata.sharedkeyenc) != 0: %lu",
                 strlen(metadata.sharedkeyenc));
    ret = 1;
    goto exit;
  }

  if (atclient_atkey_metadata_is_pubkeyhash_initialized(&metadata)) {
    ret = 1;
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "pubkeyhash is initialized when it should not be");
    goto exit;
  }

  if (strlen(metadata.pubkeyhash) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "strlen(metadata.pubkeyhash) != 0: %lu",
                 strlen(metadata.pubkeyhash));
    ret = 1;
    goto exit;
  }

  if (atclient_atkey_metadata_is_pubkeyalgo_initialized(&metadata)) {
    ret = 1;
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "pubkeyalgo is initialized when it should not be");
    goto exit;
  }

  if (strlen(metadata.pubkeyalgo) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "strlen(metadata.pubkeyalgo) != 0: %lu",
                 strlen(metadata.pubkeyalgo));
    ret = 1;
    goto exit;
  }

  if (atclient_atkey_metadata_is_encoding_initialized(&metadata)) {
    ret = 1;
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "encoding is initialized when it should not be");
    goto exit;
  }

  if (strlen(metadata.encoding) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "strlen(metadata.encoding) != 0: %lu", strlen(metadata.encoding));
    ret = 1;
    goto exit;
  }

  if (atclient_atkey_metadata_is_enckeyname_initialized(&metadata)) {
    ret = 1;
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "enckeyname is initialized when it should not be");
    goto exit;
  }

  if (strlen(metadata.enckeyname) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "strlen(metadata.enckeyname) != 0: %lu",
                 strlen(metadata.enckeyname));
    ret = 1;
    goto exit;
  }

  if (atclient_atkey_metadata_is_encalgo_initialized(&metadata)) {
    ret = 1;
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "encalgo is initialized when it should not be");
    goto exit;
  }

  if (strlen(metadata.encalgo) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "strlen(metadata.encalgo) != 0: %lu", strlen(metadata.encalgo));
    ret = 1;
    goto exit;
  }

  if (atclient_atkey_metadata_is_ivnonce_initialized(&metadata)) {
    ret = 1;
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "ivnonce is initialized when it should not be");
    goto exit;
  }

  if (strlen(metadata.ivnonce) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "strlen(metadata.ivnonce) != 0: %lu", strlen(metadata.ivnonce));
    ret = 1;
    goto exit;
  }

  if (atclient_atkey_metadata_is_skeenckeyname_initialized(&metadata)) {
    ret = 1;
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "skeenckeyname is initialized when it should not be");
    goto exit;
  }

  if (strlen(metadata.skeenckeyname) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "strlen(metadata.skeenckeyname) != 0: %lu",
                 strlen(metadata.skeenckeyname));
    ret = 1;
    goto exit;
  }

  if (atclient_atkey_metadata_is_skeencalgo_initialized(&metadata)) {
    ret = 1;
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "skeencalgo is initialized when it should not be");
    goto exit;
  }

  if (strlen(metadata.skeencalgo) != 0) {
    ret = 1;
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "strlen(metadata.skeencalgo) != 0: %lu",
                 strlen(metadata.skeencalgo));
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

  char *protocolfragment = NULL;
  const size_t expected_protocolframent_len = atclient_atkey_metadata_protocol_strlen(&metadata);

  ret = atclient_atkey_metadata_to_protocol_str(&metadata, &protocolfragment);
  if (ret != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atclient_atkey_metadata_to_protocolstr failed");
    goto exit;
  }

  const size_t actual_protocolfragment_len = strlen(protocolfragment);

  if (actual_protocolfragment_len != expected_protocolframent_len) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR,
                 "actual_protocolfragment_len != expected_protocolframent_len: %lu != %lu", actual_protocolfragment_len,
                 expected_protocolframent_len);
    ret = 1;
    goto exit;
  }

  if (actual_protocolfragment_len != expectedlen) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "actual_protocolfragment_len != expectedlen: %lu != %lu",
                 actual_protocolfragment_len, expectedlen);
    ret = 1;
    goto exit;
  }

  if (strcmp(protocolfragment, expected) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "strncmp(protocolfragment, expected) != 0: %s != %s",
                 protocolfragment, expected);
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
