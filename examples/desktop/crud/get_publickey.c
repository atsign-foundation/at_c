#include <atclient/atclient.h>
#include <atclient/atkey.h>
#include <atclient/atsign.h>
#include <atclient/constants.h>
#include <atclient/metadata.h>
#include <atlogger/atlogger.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// publickey

#define TAG "Debug"

// #define ATSIGN "@jeremy_0"
#define ATSIGN "@qt_thermostat"
#define ATKEYS_FILE_PATH "/Users/jeremytubongbanua/.atsign/keys/@qt_thermostat_key.atKeys"

#define ATCLIENT_LOGGING_LEVEL ATLOGGER_LOGGING_LEVEL_DEBUG

#define ROOT_HOST "root.atsign.org"
#define ROOT_PORT 64

#define ATKEY_NAME "publickey"
#define ATKEY_SHAREDBY "@colin"

int main() {
  int ret = 1;

  atlogger_set_logging_level(ATCLIENT_LOGGING_LEVEL);

  const size_t valuelen = 4096;
  char value[valuelen];
  memset(value, 0, valuelen);
  size_t valueolen = 0;

  atclient atclient;
  atclient_init(&atclient);

  atclient_connection root_connection;
  atclient_connection_init(&root_connection, ATCLIENT_CONNECTION_TYPE_DIRECTORY);
  atclient_connection_connect(&root_connection, ROOT_HOST, ROOT_PORT);

  atclient_atsign atsign;
  atclient_atsign_init(&atsign, ATSIGN);

  atclient_atkey atkey;
  atclient_atkey_init(&atkey);

  atclient_atkeys atkeys;
  atclient_atkeys_init(&atkeys);
  atclient_atkeys_populate_from_path(&atkeys, ATKEYS_FILE_PATH);

  atclient_atstr atkeystr;
  atclient_atstr_init(&atkeystr, ATCLIENT_ATKEY_FULL_LEN);

  if ((ret = atclient_pkam_authenticate(&atclient, &root_connection, &atkeys, atsign.atsign)) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "Failed to authenticate");
    goto exit;
  }

  if ((ret = atclient_atkey_create_publickey(&atkey, ATKEY_NAME, strlen(ATKEY_NAME), ATKEY_SHAREDBY,
                                             strlen(ATKEY_SHAREDBY), NULL, 0)) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "Failed to create public key");
    goto exit;
  }

  if ((ret = atclient_atkey_to_string(&atkey, atkeystr.str, atkeystr.size, &atkeystr.len)) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "Failed to convert to string");
    goto exit;
  }

  atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_DEBUG, "atkeystr.str (%lu): \"%.*s\"\n", atkeystr.len,
                        (int)atkeystr.len, atkeystr.str);

  ret = atclient_get_publickey(&atclient, &atkey, value, valuelen, &valueolen, true);
  if (ret != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "Failed to get public key");
    goto exit;
  }

  atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_DEBUG, "Data: \"%.*s\"\n", (int)valueolen, value);

  char metadatajsonstr[4096];
  memset(metadatajsonstr, 0, 4096);
  size_t metadatstrolen = 0;

  ret = atclient_atkey_metadata_to_jsonstr(&atkey.metadata, metadatajsonstr, 4096, &metadatstrolen);
  if (ret != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "Failed to convert metadata to json string");
    goto exit;
  }

  atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_DEBUG, "Metadata: \"%.*s\"\n", (int)metadatstrolen,
                        metadatajsonstr);

  ret = 0;
  goto exit;
exit : {
  atclient_atstr_free(&atkeystr);
  atclient_atkeys_free(&atkeys);
  atclient_atkey_free(&atkey);
  atclient_atsign_free(&atsign);
  atclient_free(&atclient);
  atclient_connection_free(&root_connection);
  return ret;
}
}
