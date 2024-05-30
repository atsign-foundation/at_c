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

static int set_up_atkeys(atclient_atkeys *atkeys, const char *atsign, const size_t atsignlen);

static int reconnect(atclient *atclient);

int main() {
  int ret = 1;

  atlogger_set_logging_level(ATLOGGER_LOGGING_LEVEL_DEBUG);

  atclient atclient1;
  atclient_init(&atclient1);

  atclient_atkeys atkeys;
  atclient_atkeys_init(&atkeys);

  char *atserver_host = NULL;
  int atserver_port = 0;

  if ((ret = set_up_atkeys(&atkeys, ATSIGN, strlen(ATSIGN))) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "Failed to set up atkeys: %d\n", ret);
    goto exit;
  }

  if ((ret = atclient_utils_find_atserver_address(ATDIRECTORY_HOST, ATDIRECTORY_PORT, ATSIGN, &atserver_host,
                                                  &atserver_port)) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "Failed to find atserver address: %d\n", ret);
    goto exit;
  }

  if ((ret = atclient_pkam_authenticate(&atclient1, atserver_host, atserver_port, &atkeys, ATSIGN)) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "Failed to PKAM authenticate.\n");
    goto exit;
  }

  bool is_connected;

  while (true) {
    if ((is_connected = atclient_is_connected(&atclient1))) {
      atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_INFO, "We are connected to the atServer! :)\n");
    } else {
      atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_INFO, "We are not connected to atServer? :O\n");
    }
    sleep(1);
  }

  ret = 0;
  goto exit;
exit: {
  atclient_free(&atclient1);
  free(atserver_host);
  return ret;
}
}

static int set_up_atkeys(atclient_atkeys *atkeys, const char *atsign, const size_t atsignlen) {
  int ret = 1;

  const size_t atkeyspathsize = 1024;
  char atkeyspath[atkeyspathsize];
  memset(atkeyspath, 0, atkeyspathsize);
  size_t atkeyspathlen;

  struct passwd *pw = getpwuid(getuid());
  const char *homedir = pw->pw_dir;
  snprintf(atkeyspath, atkeyspathsize, "%s/.atsign/keys/%s_key.atKeys", homedir, atsign);

  if ((ret = atclient_atkeys_populate_from_path(atkeys, atkeyspath)) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "Failed to populate atkeys from path: %d\n", ret);
    goto exit;
  }

  goto exit;

exit: { return ret; }
}

static int reconnect(atclient *atclient) {
  int ret = 1;

  atclient_try_reconnect(atclient);

  goto exit;
exit: { return ret; }
}