#include <atclient/atclient.h>
#include <atclient/atkey.h>
#include <atclient/atsign.h>
#include <atclient/constants.h>
#include <atclient/metadata.h>
#include <atlogger/atlogger.h>
#include <string.h>

// publickey

#define TAG "Debug"

// #define ATSIGN "@jeremy_0"
#define ATSIGN "@soccer0"
#define ATKEYS_FILE_PATH "/Users/jeremytubongbanua/.atsign/keys/@soccer0_key.atKeys"

#define ATCLIENT_LOGGING_LEVEL ATLOGGER_LOGGING_LEVEL_DEBUG

#define ROOT_HOST "root.atsign.org"
#define ROOT_PORT 64

#define ATKEY_NAME "test"
#define ATKEY_NAMESPACE "dart_playground"
#define ATKEY_SHAREDBY "@soccer0"

int main() {
  int ret = 1;

  atlogger_set_logging_level(ATLOGGER_LOGGING_LEVEL_DEBUG);

  char *atserver_host = NULL;
  int atserver_port = -1;

  const size_t valuelen = 1024;
  char value[valuelen];
  memset(value, 0, valuelen);
  size_t valueolen = 0;

  atclient atclient;
  atclient_init(&atclient);

  atclient_atsign atsign;
  atclient_atsign_init(&atsign, ATSIGN);

  atclient_atkey atkey;
  atclient_atkey_init(&atkey);

  atclient_atkeys atkeys;
  atclient_atkeys_init(&atkeys);
  atclient_atkeys_populate_from_path(&atkeys, ATKEYS_FILE_PATH);

  char *atkeystr = NULL;

  if ((ret = atclient_utils_find_atserver_address(ROOT_HOST, ROOT_PORT, atsign.atsign, &atserver_host,
                                                  &atserver_port)) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "Failed to find atserver address");
    goto exit;
  }

  if ((ret = atclient_pkam_authenticate(&atclient, atserver_host, atserver_port, &atkeys, atsign.atsign)) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "Failed to authenticate\n");
    goto exit;
  } else {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_DEBUG, "Successfully authenticated!\n");
  }
  atclient.atkeys = atkeys;
  atclient.atsign = atsign;

  if ((ret = atclient_atkey_create_selfkey(&atkey, ATKEY_NAME, strlen(ATKEY_NAME), atsign.atsign, strlen(atsign.atsign),
                                           ATKEY_NAMESPACE, strlen(ATKEY_NAMESPACE))) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "Failed to create public key\n");
    goto exit;
  } else {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_DEBUG, "Created self key\n");
  }

  if ((ret = atclient_atkey_to_string(&atkey, &atkeystr)) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "Failed to convert to string\n");
    goto exit;
  }
  const size_t atkeystrlen = strlen(atkeystr);

  atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_DEBUG, "atkeystr.str (%lu): \"%.*s\"\n", atkeystrlen, (int)(atkeystrlen),
               atkeystr);

  ret = atclient_get_selfkey(&atclient, &atkey, value, valuelen, &(valueolen));
  if (ret != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "Failed to get self key");
    goto exit;
  }

  atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_INFO, "value.str (%lu): \"%.*s\"\n", valueolen, (int)valueolen, value);

  ret = 0;
  goto exit;
exit: {
  atclient_atkey_free(&atkey);
  atclient_atkeys_free(&atkeys);
  atclient_atsign_free(&atsign);
  atclient_free(&atclient);
  free(atserver_host);
  free(atkeystr);
  return ret;
}
}
