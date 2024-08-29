#include <atclient/atclient.h>
#include <atclient/atclient_utils.h>
#include <atlogger/atlogger.h>
#include <pwd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define ATSIGN "@soccer0"

#define TAG "reconnection"

#define ATDIRECTORY_HOST "root.atsign.org"
#define ATDIRECTORY_PORT 64

int main() {
  int ret = 1;

  atlogger_set_logging_level(ATLOGGER_LOGGING_LEVEL_DEBUG);

  atclient atclient1;
  atclient_init(&atclient1);

  atclient_atkeys atkeys;
  atclient_atkeys_init(&atkeys);

  atclient_pkam_authenticate_options options;
  atclient_pkam_authenticate_options_init(&options);

  if ((ret = atclient_utils_populate_atkeys_from_homedir(&atkeys, ATSIGN)) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "Failed to set up atkeys: %d\n", ret);
    goto exit;
  }

  if ((ret = atclient_pkam_authenticate(&atclient1, ATSIGN, &atkeys, &options)) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "Failed to PKAM authenticate.\n");
    goto exit;
  }

  atclient_set_read_timeout(&atclient1, 1000);

  bool is_connected;

  while (true) {
    if ((is_connected = atclient_is_connected(&atclient1))) {
      atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_INFO, "We are connected to the atServer! :)\n");
    } else {
      atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_INFO, "We are not connected to atServer? :(\n");
      if((ret = atclient_pkam_authenticate(&atclient1, ATSIGN, &atkeys, &options)) == 0) {
        atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_INFO, "Reconnected to atServer! :)\n");
        atclient_set_read_timeout(&atclient1, 1000);
      } else {
        atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "Failed to PKAM authenticate.\n");
      }
    }
    sleep(1);
  }

  ret = 0;
  goto exit;
exit: {
  atclient_free(&atclient1);
  atclient_atkeys_free(&atkeys);
  atclient_pkam_authenticate_options_free(&options);
  return ret;
}
}
