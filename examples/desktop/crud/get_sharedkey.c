#include "atchops/sha.h"
#include <atclient/atclient.h>
#include <atclient/atkey.h>
#include <atclient/atsign.h>
#include <atclient/constants.h>
#include <atclient/metadata.h>
#include <atlogger/atlogger.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define TAG "Debug"

#define ATCLIENT_ATSIGN "@soccer0"
#define ATSIGN_ATKEYS_FILE_PATH "/Users/jeremytubongbanua/.atsign/keys/@soccer0_key.atKeys"

/**
 * To test get_sharedkey_shared_by_me_with_other:
 *      [ SENDER_ATSIGN = ATCLIENT_ATSIGN ] and [ RECIPIENT_ATSIGN = other atsign, ie "@alice" ]
 *
 * To test get_sharedkey_shared_by_other_with_me:
 *      [ SENDER_ATSIGN = other atsign, ie "@alice" ] and [ RECIPIENT_ATSIGN = ATCLIENT_ATSIGN ]
 */

#define SENDER_ATSIGN "@soccer0"    // aka "sharedby"
#define RECIPIENT_ATSIGN "@soccer99" // aka "sharedwith"

#define ATKEY_NAME "test"
#define ATKEY_NAMESPACE "dart_playground"

#define EXPECTED_DECRYPTED_VALUE_SHA_256 "d38c816073fad5249b0143fe4588013a64a4f9d50090d9a8d4c97ad0534b2592"

int main() {
  // Disable buffering
  setbuf(stdout, NULL);
  setbuf(stderr, NULL);

  int ret = 1;

  atlogger_set_logging_level(ATLOGGER_LOGGING_LEVEL_DEBUG);

  const size_t valuelen = 1024;
  atclient_atstr value;
  atclient_atstr_init(&value, valuelen);

  atclient_connection root_conn;
  atclient_connection_init(&root_conn, ATCLIENT_CONNECTION_TYPE_DIRECTORY);
  atclient_connection_connect(&root_conn, "root.atsign.org", 64);

  atclient atclient;
  atclient_init(&atclient);

  atclient_atsign atsign;
  atclient_atsign_init(&atsign, ATCLIENT_ATSIGN);

  atclient_atkey atkey;
  atclient_atkey_init(&atkey);

  atclient_atkeys atkeys;
  atclient_atkeys_init(&atkeys);
  atclient_atkeys_populate_from_path(&atkeys, ATSIGN_ATKEYS_FILE_PATH);

  atclient_atstr atkeystr;
  atclient_atstr_init(&atkeystr, ATCLIENT_ATKEY_FULL_LEN);

  if ((ret = atclient_pkam_authenticate(&atclient, &root_conn, &atkeys, ATCLIENT_ATSIGN)) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "Failed to authenticate\n");
    goto exit;
  } else {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_DEBUG, "Authenticated\n");
  }

  atclient.atkeys = atkeys;
  atclient.atsign = atsign;

  if ((ret = atclient_atkey_create_sharedkey(&atkey, ATKEY_NAME, strlen(ATKEY_NAME), SENDER_ATSIGN,
                                             strlen(SENDER_ATSIGN), RECIPIENT_ATSIGN, strlen(RECIPIENT_ATSIGN),
                                             ATKEY_NAMESPACE, strlen(ATKEY_NAMESPACE))) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "Failed to create shared key\n");
    goto exit;
  } else {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_DEBUG, "Created shared key\n");
  }

  if ((ret = atclient_atkey_to_string(&atkey, atkeystr.str, atkeystr.size, &atkeystr.len)) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "Failed to convert to string\n");
    goto exit;
  }

  atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_DEBUG, "atkeystr.str (%lu): \"%.*s\"\n", atkeystr.len,
                        (int)atkeystr.len, atkeystr.str);

  ret = atclient_get_sharedkey(&atclient, &atkey, value.str, value.size, &value.len, NULL, false);
  if (ret != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "Failed to get shared key");
    goto exit;
  }

  atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_DEBUG, "value.str (%lu): \"%.*s\"\n", value.len, (int)value.len,
                        value.str);

  const size_t value_hash_len = 32;
  unsigned char *value_hash = calloc(value_hash_len, sizeof(unsigned char));
  memset(value_hash, 0, value_hash_len);
  size_t value_hash_olen = 0;

  ret = atchops_sha_hash(MBEDTLS_MD_SHA256, (const unsigned char *)value.str, value.len, value_hash);
  if (ret != 0) {
    printf("atchops_sha_hash (failed): %d\n", ret);
    goto exit;
  }

  char *hex_value_hash = calloc(65, sizeof(char));
  for (size_t i = 0; i < value_hash_len; i++) {
    sprintf(hex_value_hash + i * 2, "%02x", value_hash[i]);
  }

  atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_DEBUG, "sha256(value) : %s\n", hex_value_hash);

  if ((ret = memcmp(hex_value_hash, EXPECTED_DECRYPTED_VALUE_SHA_256, 64))) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_DEBUG,
                          "sha256(value) NOT equal to EXPECTED_DECRYPTED_VALUE_SHA_256\n");
  } else {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_DEBUG,
                          "sha256(value) equal to EXPECTED_DECRYPTED_VALUE_SHA_256\n");
  }
  free(value_hash);
  free(hex_value_hash);
  goto exit;
exit : {
  atclient_atstr_free(&value);
  atclient_atkey_free(&atkey);
  atclient_atkeys_free(&atkeys);
  atclient_atstr_free(&atkeystr);
  atclient_atsign_free(&atsign);
  atclient_free(&atclient);
  return ret;
}
}
