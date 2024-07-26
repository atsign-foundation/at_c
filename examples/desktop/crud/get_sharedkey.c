#include "atchops/sha.h"
#include <atclient/atclient.h>
#include <atclient/atkey.h>
#include <atclient/constants.h>
#include <atclient/metadata.h>
#include <atlogger/atlogger.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define TAG "Debug"

#define ROOT_HOST "root.atsign.org"
#define ROOT_PORT 64

#define ATCLIENT_ATSIGN "@soccer0"
#define ATSIGN_ATKEYS_FILE_PATH "/Users/jeremytubongbanua/.atsign/keys/@soccer0_key.atKeys"

/**
 * To test get_sharedkey_shared_by_me_with_other:
 *      [ SENDER_ATSIGN = ATCLIENT_ATSIGN ] and [ RECIPIENT_ATSIGN = other atsign, ie "@alice" ]
 *
 * To test get_sharedkey_shared_by_other_with_me:
 *      [ SENDER_ATSIGN = other atsign, ie "@alice" ] and [ RECIPIENT_ATSIGN = ATCLIENT_ATSIGN ]
 */

#define SENDER_ATSIGN "@soccer0"     // aka "sharedby"
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

  const size_t valuesize = 1024;
  char value[valuesize];
  memset(value, 0, sizeof(char) * valuesize);
  size_t valuelen;

  char *atserver_host = NULL;
  int atserver_port = -1;

  atclient atclient;
  atclient_init(&atclient);

  const char *atsign = ATCLIENT_ATSIGN;

  atclient_atkey atkey;
  atclient_atkey_init(&atkey);

  atclient_atkeys atkeys;
  atclient_atkeys_init(&atkeys);
  atclient_atkeys_populate_from_path(&atkeys, ATSIGN_ATKEYS_FILE_PATH);

  char *atkeystr = NULL;

  if ((ret = atclient_utils_find_atserver_address(ROOT_HOST, ROOT_PORT, atsign, &atserver_host,
                                                  &atserver_port)) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "Failed to find atserver address");
    goto exit;
  }

  if ((ret = atclient_pkam_authenticate(&atclient, atserver_host, atserver_port, &atkeys, atsign)) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "Failed to authenticate\n");
    goto exit;
  } else {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_DEBUG, "Authenticated\n");
  }

  if ((ret = atclient_atkey_create_shared_key(&atkey, ATKEY_NAME, SENDER_ATSIGN, RECIPIENT_ATSIGN, ATKEY_NAMESPACE)) !=
      0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "Failed to create shared key\n");
    goto exit;
  } else {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_DEBUG, "Created shared key\n");
  }

  if ((ret = atclient_atkey_to_string(&atkey, &atkeystr)) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "Failed to convert to string\n");
    goto exit;
  }
  const size_t atkeystrlen = strlen(atkeystr);

  atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_DEBUG, "atkeystr.str (%lu): \"%.*s\"\n", atkeystrlen, (int)atkeystrlen,
               atkeystr);

  ret = atclient_get_shared_key(&atclient, &atkey, value, NULL);
  if (ret != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "Failed to get shared key");
    goto exit;
  }

  atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_DEBUG, "value.str (%lu): \"%.*s\"\n", valuelen, (int)valuelen, value);

  const size_t value_hash_len = 32;
  unsigned char *value_hash = calloc(value_hash_len, sizeof(unsigned char));
  memset(value_hash, 0, value_hash_len);
  size_t value_hash_olen = 0;

  ret = atchops_sha_hash(ATCHOPS_MD_SHA256, (const unsigned char *)value, valuelen, value_hash);
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
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_DEBUG, "sha256(value) NOT equal to EXPECTED_DECRYPTED_VALUE_SHA_256\n");
  } else {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_DEBUG, "sha256(value) equal to EXPECTED_DECRYPTED_VALUE_SHA_256\n");
  }
  free(value_hash);
  free(hex_value_hash);
  goto exit;
exit: {
  atclient_atkey_free(&atkey);
  atclient_atkeys_free(&atkeys);
  atclient_free(&atclient);
  free(atserver_host);
  free(atkeystr);
  return ret;
}
}
