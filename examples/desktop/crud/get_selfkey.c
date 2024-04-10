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

  atclient_atlogger_set_logging_level(ATLOGGER_LOGGING_LEVEL_DEBUG);

  const size_t valuelen = 1024;
  char value[valuelen];
  memset(value, 0, valuelen);
  size_t valueolen = 0;

  atclient_connection root_conn;
  atclient_connection_init(&root_conn);
  atclient_connection_connect(&root_conn, ROOT_HOST, ROOT_PORT);

  atclient atclient;
  atclient_init(&atclient);

  atclient_atsign atsign;
  atclient_atsign_init(&atsign, ATSIGN);

  atclient_atkey atkey;
  atclient_atkey_init(&atkey);

  atclient_atkeys atkeys;
  atclient_atkeys_init(&atkeys);
  atclient_atkeys_populate_from_path(&atkeys, ATKEYS_FILE_PATH);

  atclient_atstr atkeystr;
  atclient_atstr_init(&atkeystr, ATCLIENT_ATKEY_FULL_LEN);

  if ((ret = atclient_pkam_authenticate(&atclient, &root_conn, &atkeys, &atsign)) != 0) {
    atclient_atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "Failed to authenticate\n");
    goto exit;
  } else {
    atclient_atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_DEBUG, "Successfully authenticated!\n");
  }
  atclient.atkeys = atkeys;
  atclient.atsign = atsign;

  if ((ret = atclient_atkey_create_selfkey(&atkey, ATKEY_NAME, strlen(ATKEY_NAME), atsign.atsign, strlen(atsign.atsign),
                                           ATKEY_NAMESPACE, strlen(ATKEY_NAMESPACE))) != 0) {
    atclient_atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "Failed to create public key\n");
    goto exit;
  } else {
    atclient_atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_DEBUG, "Created self key\n");
  }

  if ((ret = atclient_atkey_to_string(&atkey, atkeystr.str, atkeystr.len, &atkeystr.olen)) != 0) {
    atclient_atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "Failed to convert to string\n");
    goto exit;
  }

  atclient_atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_DEBUG, "atkeystr.str (%lu): \"%.*s\"\n", atkeystr.olen,
                        (int)atkeystr.olen, atkeystr.str);

  ret = atclient_get_selfkey(&atclient, &atkey, value, valuelen, &(valueolen));
  if (ret != 0) {
    atclient_atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "Failed to get self key");
    goto exit;
  }

  atclient_atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_INFO, "value.str (%lu): \"%.*s\"\n", valueolen, (int)valueolen,
                        value);

  ret = 0;
  goto exit;
exit : {
  atclient_atkey_free(&atkey);
  atclient_atkeys_free(&atkeys);
  atclient_atstr_free(&atkeystr);
  atclient_atsign_free(&atsign);
  atclient_free(&atclient);
  atclient_connection_free(&root_conn);
  return ret;
}
}
