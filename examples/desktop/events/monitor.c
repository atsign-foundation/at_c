#include <atclient/atclient.h>
#include <atclient/atkey.h>
#include <atclient/atsign.h>
#include <atclient/constants.h>
#include <atclient/metadata.h>
#include <atclient/notification.h>
#include <atlogger/atlogger.h>
#include <string.h>

#define TAG "Debug"

#define ATSIGN "@qt_app_2"
#define OATSIGN "@qt_thermostat"
#define ATKEYS_FILE_PATH "/Users/chant/.atsign/keys/@qt_app_2_key.atKeys"

#define ROOT_HOST "root.atsign.org"
#define ROOT_PORT 64

static void monitor_handler(const atclient_atnotification *);

int main() {
  int ret = 1;

  atclient_atlogger_set_logging_level(ATLOGGER_LOGGING_LEVEL_DEBUG);

  const size_t valuelen = 1024;
  char value[valuelen];
  memset(value, 0, sizeof(char) * valuelen);
  size_t valueolen = 0;

  atclient atclient;
  atclient_init(&atclient);

  atclient_connection root_connection;
  atclient_connection_init(&root_connection);
  atclient_connection_connect(&root_connection, ROOT_HOST, ROOT_PORT, NULL);

  atclient_atsign atsign;
  atclient_atsign_init(&atsign, ATSIGN);

  atclient_atkeys atkeys;
  atclient_atkeys_init(&atkeys);
  atclient_atkeys_populate_from_path(&atkeys, ATKEYS_FILE_PATH);

  if ((ret = atclient_pkam_authenticate(&atclient, &root_connection, atkeys, atsign.atsign, strlen(atsign.atsign),
                                        NULL)) != 0) {
    atclient_atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "Failed to authenticate");
    goto exit;
  }

  atclient_monitor_params params = {
      .regex = ".*",
      .handler = monitor_handler,
  };

  printf("Starting monitor\n");
  if ((ret = atclient_monitor(ROOT_HOST, ROOT_PORT, atsign, atkeys, &params))) {
    atclient_atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "Monitor crashed");
    goto exit;
  }

  ret = 0;
  goto exit;
exit: {
  atclient_atkeys_free(&atkeys);
  atclient_atsign_free(&atsign);
  atclient_free(&atclient);
  atclient_connection_free(&root_connection);
  return ret;
}
}

void monitor_handler(const atclient_atnotification *event) {
  atclient_atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_DEBUG, "Event received");
}
