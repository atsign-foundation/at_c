#include "atclient/metadata.h"
#include "atlogger/atlogger.h"
#include <stddef.h>
#include <string.h>
#include <stdlib.h>

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

  if ((ret = atclient_atkey_metadata_from_jsonstr(&metadata, TEST_ATKEY_METADATA_FROM_JSONSTR)) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atclient_atkey_metadata_from_jsonstr failed\n");
    goto exit;
  }

  if (!atclient_atkey_metadata_is_createdby_initialized(&metadata)) {
    ret = 1;
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atclient_atkey_metadata_is_createdby_initialized failed\n");
    goto exit;
  }

  if (strcmp(metadata.createdby, "@qt_thermostat") != 0) {
    ret = 1;
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "metadata.createdby != @qt_thermostat: %s", metadata.createdby);
    goto exit;
  }

  if (!atclient_atkey_metadata_is_updatedby_initialized(&metadata)) {
    ret = 1;
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atclient_atkey_metadata_is_updatedby_initialized failed\n");
    goto exit;
  }

  if (strcmp(metadata.updatedby, "@qt_thermostat") != 0) {
    ret = 1;
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "metadata.updatedby.atsign != @qt_thermostat: %s\n",
                 metadata.updatedby);
    goto exit;
  }

  if (!atclient_atkey_metadata_is_createdat_initialized(&metadata)) {
    ret = 1;
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atclient_atkey_metadata_is_createdat_initialized failed\n");
    goto exit;
  }

  if (strcmp(metadata.createdat, "2024-02-17 19:54:12.037Z") != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "metadata.createdat != 2024-02-17 19:54:12.037Z: %s\n",
                 metadata.createdat);
    ret = 1;
    goto exit;
  }

  if (!atclient_atkey_metadata_is_updatedat_initialized(&metadata)) {
    ret = 1;
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atclient_atkey_metadata_is_updatedat_initialized failed\n");
    goto exit;
  }

  if (strcmp(metadata.updatedat, "2024-02-17 19:54:12.037Z") != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "metadata.updatedat != 2024-02-17 19:54:12.037Z: %s\n",
                 metadata.updatedat);
    ret = 1;
    goto exit;
  }

  if (!atclient_atkey_metadata_is_expiresat_initialized(&metadata)) {
    ret = 1;
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atclient_atkey_metadata_is_expiresat_initialized failed\n");
    goto exit;
  }

  if (strcmp(metadata.expiresat, "2024-02-17 19:55:38.437Z") != 0) {
    ret = 1;
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "metadata.expiresat != 2024-02-17 19:55:38.437Z: %s\n",
                 metadata.expiresat);
    goto exit;
  }

  if (!atclient_atkey_metadata_is_status_initialized(&metadata)) {
    ret = 1;
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atclient_atkey_metadata_is_status_initialized failed\n");
    goto exit;
  }

  if (strcmp(metadata.status, "active") != 0) {
    ret = 1;
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "metadata.status != active: %s\n", metadata.status);
    goto exit;
  }

  if (!atclient_atkey_metadata_is_version_initialized(&metadata)) {
    ret = 1;
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atclient_atkey_metadata_is_version_initialized failed\n");
    goto exit;
  }

  if (metadata.version != 0) {
    ret = 1;
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "metadata.version != 0: %d\n", metadata.version);
    goto exit;
  }

  if (!atclient_atkey_metadata_is_ttl_initialized(&metadata)) {
    ret = 1;
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atclient_atkey_metadata_is_ttl_initialized failed\n");
    goto exit;
  }

  if (metadata.ttl != 86400) {
    ret = 1;
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "metadata.ttl != 86400: %ld\n", metadata.ttl);
    goto exit;
  }

  if (!atclient_atkey_metadata_is_isbinary_initialized(&metadata)) {
    ret = 1;
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atclient_atkey_metadata_isbinary_initialized failed\n");
    goto exit;
  }

  if (metadata.isbinary != false) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "metadata.isbinary != false: %d\n", metadata.isbinary);
    ret = 1;
    goto exit;
  }

  if (!atclient_atkey_metadata_is_isencrypted_initialized(&metadata)) {
    ret = 1;
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atclient_atkey_metadata_isencrypted_initialized failed\n");
    goto exit;
  }

  if (metadata.isencrypted != false) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "metadata.isencrypted != false: %d\n", metadata.isencrypted);
    ret = 1;
    goto exit;
  }

  if (atclient_atkey_metadata_is_iscached_initialized(&metadata)) {
    ret = 1;
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR,
                 "atclient_atkey_metadata_iscached_initialized was initialized when it should not be\n");
    goto exit;
  }

  if (atclient_atkey_metadata_is_availableat_initialized(&metadata)) {
    ret = 1;
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atclient_atkey_metadata_isavailableat_initialized is intiialized when it should not be\n");
    goto exit;
  }

  if(atclient_atkey_metadata_is_refreshat_initialized(&metadata)) {
    ret = 1;
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atclient_atkey_metadata_isrefreshat_initialized is intiialized when it should not be\n");
    goto exit;
  }

  if (atclient_atkey_metadata_is_datasignature_initialized(&metadata)) {
    ret = 1;
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "datasignature is initialized when it should not be\n");
    goto exit;
  }

  if (atclient_atkey_metadata_is_sharedkeystatus_initialized(&metadata)) {
    ret = 1;
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "sharedby is initialized when it should not be\n");
    goto exit;
  }

  if (atclient_atkey_metadata_is_sharedkeyenc_initialized(&metadata)) {
    ret = 1;
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "sharedkeyenc is initialized when it should not be\n");
    goto exit;
  }

  if (atclient_atkey_metadata_is_pubkeyhash_initialized(&metadata)) {
    ret = 1;
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "pubkeyhash is initialized when it should not be\n");
    goto exit;
  }

  if (atclient_atkey_metadata_is_pubkeyalgo_initialized(&metadata)) {
    ret = 1;
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "pubkeyalgo is initialized when it should not be\n");
    goto exit;
  }

  if (atclient_atkey_metadata_is_encoding_initialized(&metadata)) {
    ret = 1;
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "encoding is initialized when it should not be\n");
    goto exit;
  }

  if (atclient_atkey_metadata_is_enckeyname_initialized(&metadata)) {
    ret = 1;
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "enckeyname is initialized when it should not be\n");
    goto exit;
  }

  if (atclient_atkey_metadata_is_encalgo_initialized(&metadata)) {
    ret = 1;
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "encalgo is initialized when it should not be\n");
    goto exit;
  }

  if (atclient_atkey_metadata_is_ivnonce_initialized(&metadata)) {
    ret = 1;
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "ivnonce is initialized when it should not be\n");
    goto exit;
  }

  if (atclient_atkey_metadata_is_skeenckeyname_initialized(&metadata)) {
    ret = 1;
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "skeenckeyname is initialized when it should not be\n");
    goto exit;
  }

  if (atclient_atkey_metadata_is_skeencalgo_initialized(&metadata)) {
    ret = 1;
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "skeencalgo is initialized when it should not be\n");
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
  atclient_atkey_metadata_set_ivnonce(&metadata, "abcdefghijk");

  char *protocolfragment = NULL;
  const size_t expected_protocolframent_len = atclient_atkey_metadata_protocol_strlen(&metadata);

  if ((ret = atclient_atkey_metadata_to_protocol_str(&metadata, &protocolfragment)) != 0) {
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

  char *jsonstr = NULL;

  if ((ret = atclient_atkey_metadata_from_jsonstr(&metadata, TEST_ATKEY_METADATA_FROM_JSONSTR)) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atclient_atkey_metadata_from_jsonstr failed");
    goto exit;
  }

  if ((ret = atclient_atkey_metadata_to_jsonstr(&metadata, &jsonstr)) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atclient_atkey_metadata_to_jsonstr failed");
    goto exit;
  }

  ret = 0;
  goto exit;
exit: {
  atclient_atkey_metadata_free(&metadata);
  free(jsonstr);
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
