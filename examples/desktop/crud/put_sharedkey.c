#include <atclient/atclient.h>
#include <atclient/atkey.h>
#include <atclient/constants.h>
#include <atclient/metadata.h>
#include <atlogger/atlogger.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// publickey

#define TAG "Debug"

// #define ATSIGN "@jeremy_0"
#define ATSIGN "@soccer0"
#define ATKEYS_FILE_PATH "/Users/jeremytubongbanua/.atsign/keys/@soccer0_key.atKeys"

#define ATKEY_KEY "test"
#define ATKEY_NAMESPACE "dart_playground"
#define ATKEY_VALUE "test value"
#define ATKEY_SHAREDWITH "@soccer99"

#define ROOT_HOST "root.atsign.org"
#define ROOT_PORT 64

int main() {
  int ret = 1;

  atlogger_set_logging_level(ATLOGGER_LOGGING_LEVEL_DEBUG);

  const size_t valuesize = 2048;
  char value[valuesize];
  memset(value, 0, sizeof(char) * valuesize);
  size_t valueolen = 0;

  atclient atclient;
  atclient_init(&atclient);

  const char *atsign = ATSIGN;

  char *atserver_host = NULL;
  int atserver_port = -1;

  atclient_atkey atkey;
  atclient_atkey_init(&atkey);

  atclient_atkeys atkeys;
  atclient_atkeys_init(&atkeys);
  atclient_atkeys_populate_from_path(&atkeys, ATKEYS_FILE_PATH);

  char *atkeystr = NULL;

  if ((ret = atclient_utils_find_atserver_address(ROOT_HOST, ROOT_PORT, atsign, &atserver_host,
                                                  &atserver_port)) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "Failed to find atserver address");
    goto exit;
  }

  if ((ret = atclient_pkam_authenticate(&atclient, atserver_host, atserver_port, &atkeys, atsign)) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "Failed to authenticate");
    goto exit;
  }

  if ((ret = atclient_atkey_create_shared_key(&atkey, ATKEY_KEY, ATSIGN, ATKEY_SHAREDWITH, ATKEY_NAMESPACE)) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "Failed to create public key");
    goto exit;
  }

  atclient_atkey_metadata_set_ttl(&atkey.metadata, 60 * 1000 * 10); // 10 minutes

  if ((ret = atclient_atkey_to_string(&atkey, &atkeystr)) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "Failed to convert to string");
    goto exit;
  }
  const size_t atkeystrlen = strlen(atkeystr);

  atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_DEBUG, "Putting atkeystr.str (%lu): \"%.*s\"\n", atkeystrlen,
               (int)atkeystrlen, atkeystr);

  if ((ret = atclient_put(&atclient, &atkey, ATKEY_VALUE, strlen(ATKEY_VALUE), NULL) != 0)) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "Failed to put public key");
    goto exit;
  }

  atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_DEBUG, "Done put.\n");

  ret = 0;
  goto exit;
exit: {
  atclient_atkeys_free(&atkeys);
  atclient_atkey_free(&atkey);
  atclient_free(&atclient);
  free(atserver_host);
  free(atkeystr);
  return ret;
}
}
