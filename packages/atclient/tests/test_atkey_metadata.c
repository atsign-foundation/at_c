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
//  "is_encrypted":false
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
        \"is_encrypted\":false                       \
    }"

static int test_atkey_metadata_from_jsonstr() {
  int ret = 1;

  atclient_atkey_metadata metadata;
  atclient_atkey_metadata_init(&metadata);

  if ((ret = atclient_atkey_metadata_from_json_str(&metadata, TEST_ATKEY_METADATA_FROM_JSONSTR)) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atclient_atkey_metadata_from_json_str failed\n");
    goto exit;
  }

  if (!atclient_atkey_metadata_is_created_by_initialized(&metadata)) {
    ret = 1;
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atclient_atkey_metadata_is_created_by_initialized failed\n");
    goto exit;
  }

  if (strcmp(metadata.created_by, "@qt_thermostat") != 0) {
    ret = 1;
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "metadata.created_by != @qt_thermostat: %s", metadata.created_by);
    goto exit;
  }

  if (!atclient_atkey_metadata_is_updated_by_initialized(&metadata)) {
    ret = 1;
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atclient_atkey_metadata_is_updated_by_initialized failed\n");
    goto exit;
  }

  if (strcmp(metadata.updated_by, "@qt_thermostat") != 0) {
    ret = 1;
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "metadata.updated_by.atsign != @qt_thermostat: %s\n",
                 metadata.updated_by);
    goto exit;
  }

  if (!atclient_atkey_metadata_is_created_at_initialized(&metadata)) {
    ret = 1;
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atclient_atkey_metadata_is_created_at_initialized failed\n");
    goto exit;
  }

  if (strcmp(metadata.created_at, "2024-02-17 19:54:12.037Z") != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "metadata.created_at != 2024-02-17 19:54:12.037Z: %s\n",
                 metadata.created_at);
    ret = 1;
    goto exit;
  }

  if (!atclient_atkey_metadata_is_updated_at_initialized(&metadata)) {
    ret = 1;
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atclient_atkey_metadata_is_updated_at_initialized failed\n");
    goto exit;
  }

  if (strcmp(metadata.updated_at, "2024-02-17 19:54:12.037Z") != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "metadata.updated_at != 2024-02-17 19:54:12.037Z: %s\n",
                 metadata.updated_at);
    ret = 1;
    goto exit;
  }

  if (!atclient_atkey_metadata_is_expires_at_initialized(&metadata)) {
    ret = 1;
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atclient_atkey_metadata_is_expires_at_initialized failed\n");
    goto exit;
  }

  if (strcmp(metadata.expires_at, "2024-02-17 19:55:38.437Z") != 0) {
    ret = 1;
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "metadata.expires_at != 2024-02-17 19:55:38.437Z: %s\n",
                 metadata.expires_at);
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

  if (!atclient_atkey_metadata_is_is_binary_initialized(&metadata)) {
    ret = 1;
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atclient_atkey_metadata_is_is_binary_initialized failed\n");
    goto exit;
  }

  if (metadata.is_binary != false) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "metadata.is_binary != false: %d\n", metadata.is_binary);
    ret = 1;
    goto exit;
  }

  if (!atclient_atkey_metadata_is_is_encrypted_initialized(&metadata)) {
    ret = 1;
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atclient_atkey_metadata_is_is_encrypted_initialized failed\n");
    goto exit;
  }

  if (metadata.is_encrypted != false) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "metadata.is_encrypted != false: %d\n", metadata.is_encrypted);
    ret = 1;
    goto exit;
  }

  if (atclient_atkey_metadata_is_is_cached_initialized(&metadata)) {
    ret = 1;
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR,
                 "atclient_atkey_metadata_iscached_initialized was initialized when it should not be\n");
    goto exit;
  }

  if (atclient_atkey_metadata_is_available_at_initialized(&metadata)) {
    ret = 1;
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atclient_atkey_metadata_isavailableat_initialized is intiialized when it should not be\n");
    goto exit;
  }

  if(atclient_atkey_metadata_is_refresh_at_initialized(&metadata)) {
    ret = 1;
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atclient_atkey_metadata_isrefreshat_initialized is intiialized when it should not be\n");
    goto exit;
  }

  if (atclient_atkey_metadata_is_data_signature_initialized(&metadata)) {
    ret = 1;
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "data_signature is initialized when it should not be\n");
    goto exit;
  }

  if (atclient_atkey_metadata_is_shared_key_status_initialized(&metadata)) {
    ret = 1;
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "shared_by is initialized when it should not be\n");
    goto exit;
  }

  if (atclient_atkey_metadata_is_shared_key_enc_initialized(&metadata)) {
    ret = 1;
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "shared_key_enc is initialized when it should not be\n");
    goto exit;
  }

  if (atclient_atkey_metadata_is_pub_key_hash_initialized(&metadata)) {
    ret = 1;
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "pub_key_hash is initialized when it should not be\n");
    goto exit;
  }

  if (atclient_atkey_metadata_is_pub_key_algo_initialized(&metadata)) {
    ret = 1;
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "pub_key_algo is initialized when it should not be\n");
    goto exit;
  }

  if (atclient_atkey_metadata_is_encoding_initialized(&metadata)) {
    ret = 1;
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "encoding is initialized when it should not be\n");
    goto exit;
  }

  if (atclient_atkey_metadata_is_enc_key_name_initialized(&metadata)) {
    ret = 1;
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "enc_key_name is initialized when it should not be\n");
    goto exit;
  }

  if (atclient_atkey_metadata_is_enc_algo_initialized(&metadata)) {
    ret = 1;
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "enc_algo is initialized when it should not be\n");
    goto exit;
  }

  if (atclient_atkey_metadata_is_iv_nonce_initialized(&metadata)) {
    ret = 1;
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "iv_nonce is initialized when it should not be\n");
    goto exit;
  }

  if (atclient_atkey_metadata_is_ske_enc_key_name_initialized(&metadata)) {
    ret = 1;
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "ske_enc_key_name is initialized when it should not be\n");
    goto exit;
  }

  if (atclient_atkey_metadata_is_ske_enc_algo_initialized(&metadata)) {
    ret = 1;
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "ske_enc_algo is initialized when it should not be\n");
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

  const char *expected = ":ttr:-1:isBinary:true:is_encrypted:true:iv_nonce:abcdefghijk";
  const size_t expectedlen = strlen(expected);

  atclient_atkey_metadata metadata;
  atclient_atkey_metadata_init(&metadata);

  atclient_atkey_metadata_set_ttr(&metadata, -1);
  atclient_atkey_metadata_set_is_binary(&metadata, true);
  atclient_atkey_metadata_set_is_encrypted(&metadata, true);
  atclient_atkey_metadata_set_is_cached(&metadata, true);
  atclient_atkey_metadata_set_iv_nonce(&metadata, "abcdefghijk");

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

  if ((ret = atclient_atkey_metadata_from_json_str(&metadata, TEST_ATKEY_METADATA_FROM_JSONSTR)) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atclient_atkey_metadata_from_json_str failed");
    goto exit;
  }

  if ((ret = atclient_atkey_metadata_to_json_str(&metadata, &jsonstr)) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atclient_atkey_metadata_to_json_str failed");
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
