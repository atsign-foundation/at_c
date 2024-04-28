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

#define ATKEY_KEY "test"
#define ATKEY_NAMESPACE "dart_playground"
#define ATKEY_VALUE "test value"

int main() {
  int ret = 1;

  atlogger_set_logging_level(ATLOGGER_LOGGING_LEVEL_DEBUG);

  const size_t valuelen = 1024;
  char value[valuelen];
  memset(value, 0, sizeof(char) * valuelen);
  size_t valueolen = 0;

  atclient atclient;
  atclient_init(&atclient);

  atclient_connection root_connection;
  atclient_connection_init(&root_connection);
  atclient_connection_connect(&root_connection, "root.atsign.org", 64);

  atclient_atsign atsign;
  atclient_atsign_init(&atsign, ATSIGN);

  atclient_atkey atkey;
  atclient_atkey_init(&atkey);

  atclient_atkeys atkeys;
  atclient_atkeys_init(&atkeys);
  atclient_atkeys_populate_from_path(&atkeys, ATKEYS_FILE_PATH);

  atclient_atstr atkeystr;
  atclient_atstr_init(&atkeystr, ATCLIENT_ATKEY_FULL_LEN);

    if((ret = atclient_pkam_authenticate(&atclient, &root_connection, atkeys, atsign.atsign, strlen(atsign.atsign))) != 0) {
        atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "Failed to authenticate");
        goto exit;
    }

  if ((ret = atclient_atkey_create_publickey(&atkey, ATKEY_KEY, strlen(ATKEY_KEY), ATSIGN, strlen(ATSIGN),
                                             ATKEY_NAMESPACE, strlen(ATKEY_NAMESPACE))) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "Failed to create public key");
    goto exit;
  }

  atclient_atkey_metadata_set_ttl(&atkey.metadata, 60 * 1000 * 10); // 10 minutes
  atclient_atkey_metadata_set_ccd(&atkey.metadata, true);

  if ((ret = atclient_atkey_to_string(&atkey, atkeystr.str, atkeystr.len, &atkeystr.olen)) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "Failed to convert to string");
    goto exit;
  }

  atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_DEBUG, "atkeystr.str (%lu): \"%.*s\"\n", atkeystr.olen,
                        (int)atkeystr.olen, atkeystr.str);

  if ((ret = atclient_put(&atclient, &root_connection, &atkey, ATKEY_VALUE, strlen(ATKEY_VALUE), NULL) != 0)) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "Failed to put public key");
    goto exit;
  }

  // atclient_get_publickey
  if ((ret = atclient_get_publickey(&atclient, &root_connection, &atkey, value, valuelen, &valueolen, true)) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "Failed to get public key");
    goto exit;
  }

  atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_DEBUG, "value (%lu): \"%.*s\"\n", valueolen, (int)valueolen, value);

  ret = 0;
  goto exit;
exit: {
    atclient_atstr_free(&atkeystr);
    atclient_atkeys_free(&atkeys);
    atclient_atkey_free(&atkey);
    atclient_atsign_free(&atsign);
    atclient_free(&atclient);
    atclient_connection_free(&root_connection);
    return ret;
}
}
