#include <atclient/atclient.h>
#include <atclient/atkey.h>
#include <atclient/atsign.h>
#include <atclient/metadata.h>
#include <atlogger/atlogger.h>
#include <string.h>

#define TAG "Debug"

// #define ATSIGN "@jeremy_0"
#define ATSIGN "@qt_thermostat"
#define ATKEYS_FILE_PATH "/Users/jeremytubongbanua/.atsign/keys/@qt_thermostat_key.atKeys"

#define ATCLIENT_LOGGING_LEVEL ATLOGGER_LOGGING_LEVEL_DEBUG

#define ATKEY_NAME "test"
#define ATKEY_NAMESPACE "dart_playground"

int main() {
  int ret = 1;

  atlogger_set_logging_level(ATCLIENT_LOGGING_LEVEL);

  atclient atclient;
  atclient_connection root_conn;
  atclient_atsign atsign;
  atclient_atkey atkey;
  atclient_atkeys atkeys;

  atclient_init(&atclient);
  atclient_connection_init(&root_conn);
  atclient_atsign_init(&atsign, ATSIGN);
  atclient_atkey_init(&atkey);
  atclient_atkeys_init(&atkeys);

  if ((ret = atclient_connection_connect(&root_conn, "root.atsign.org", 64)) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "Failed to connect");
    goto exit;
  }

  if ((ret = atclient_atkeys_populate_from_path(&atkeys, ATKEYS_FILE_PATH)) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "Failed to populate atkeys");
    goto exit;
  }

  if ((ret = atclient_atkey_create_selfkey(&atkey, ATKEY_NAME, strlen(ATKEY_NAME), atsign.atsign, strlen(atsign.atsign),
                                           ATKEY_NAME, strlen(ATKEY_NAME))) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "Failed to create selfkey");
    goto exit;
  }

  if ((ret = atclient_pkam_authenticate(&atclient, &root_conn, &atkeys, atsign.atsign)) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "Failed to authenticate");
    goto exit;
  }

  if ((ret = atclient_delete(&atclient, &atkey)) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "Failed to delete");
    goto exit;
  }

  ret = 0;
  goto exit;
exit: {
  atclient_free(&atclient);
  atclient_connection_free(&root_conn);
  atclient_atsign_free(&atsign);
  atclient_atkey_free(&atkey);
  atclient_atkeys_free(&atkeys);
  return ret;
}
}
