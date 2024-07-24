#include <atclient/atclient.h>
#include <atclient/atkey.h>
#include <atclient/metadata.h>
#include <atlogger/atlogger.h>
#include <string.h>
#include <stdlib.h>

#define TAG "Debug"

#define ROOT_HOST "root.atsign.org"
#define ROOT_PORT 64

// #define ATSIGN "@jeremy_0"
#define ATSIGN "@qt_thermostat"
#define ATKEYS_FILE_PATH "/Users/jeremytubongbanua/.atsign/keys/@qt_thermostat_key.atKeys"

#define ATCLIENT_LOGGING_LEVEL ATLOGGER_LOGGING_LEVEL_DEBUG

#define ATKEY_NAME "test"
#define ATKEY_NAMESPACE "dart_playground"

int main() {
  int ret = 1;

  atlogger_set_logging_level(ATCLIENT_LOGGING_LEVEL);

  char *atserver_host = NULL;
  int atserver_port = -1;

  atclient atclient;
  atclient_atkey atkey;
  atclient_atkeys atkeys;
  const char *atsign = ATSIGN;

  atclient_init(&atclient);
  atclient_atkey_init(&atkey);
  atclient_atkeys_init(&atkeys);

  if ((ret = atclient_atkeys_populate_from_path(&atkeys, ATKEYS_FILE_PATH)) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "Failed to populate atkeys");
    goto exit;
  }

  if ((ret = atclient_atkey_create_self_key(&atkey, ATKEY_NAME, atsign, ATKEY_NAME)) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "Failed to create selfkey");
    goto exit;
  }

  if ((ret = atclient_utils_find_atserver_address(ROOT_HOST, ROOT_PORT, atsign, &atserver_host,
                                                  &atserver_port)) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "Failed to find atserver address");
    goto exit;
  }

  if ((ret = atclient_pkam_authenticate(&atclient, atserver_host, atserver_port, &atkeys, atsign)) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "Failed to authenticate");
    goto exit;
  }

  if ((ret = atclient_delete(&atclient, &atkey, NULL)) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "Failed to delete");
    goto exit;
  }

  ret = 0;
  goto exit;
exit: {
  atclient_free(&atclient);
  free(atserver_host);
  atclient_atkey_free(&atkey);
  atclient_atkeys_free(&atkeys);
  return ret;
}
}
