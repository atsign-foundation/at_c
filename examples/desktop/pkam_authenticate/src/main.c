#include <atclient/atclient.h>
#include <atclient/atkeys_file.h>
#include <atlogger/atlogger.h>
#include <stdio.h>

#define ROOT_HOST "root.atsign.org"
#define ROOT_PORT 64

#define atkeys_file_PATH "/home/realvarx/.atsign/keys/@expensiveferret_key.atKeys"
#define ATSIGN "@expensiveferret"

#define TAG "pkam_authenticate"

int main(int argc, char **argv) {
  int ret = 1;

  atlogger_set_logging_level(ATLOGGER_LOGGING_LEVEL_INFO);

  // 1. init atkeys
  char *atserver_host = NULL;
  int atserver_port = -1;

  // 1a. read `atkeys_file` struct
  atclient_atkeys_file atkeys_file;
  atclient_atkeys_file_init(&atkeys_file);
  ret = atclient_atkeys_file_from_path(&atkeys_file, atkeys_file_PATH);
  // printf("atkeys_file_read_code: %d\n", ret);
  if (ret != 0) {
    goto exit;
  }
  atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_INFO, "atclient_atkeys_file_read: %d\n", ret);

  // 1b. populate `atkeys` struct
  atclient_atkeys atkeys;
  atclient_atkeys_init(&atkeys);
  ret = atclient_atkeys_populate_from_atkeys_file(&atkeys, atkeys_file);
  // printf("atkeys_populate_code: %d\n", ret);
  if (ret != 0) {
    goto exit;
  }
  atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_INFO, "atclient_atkeys_populate_from_atkeys_file: %d\n", ret);

  // 2. pkam auth
  atclient atclient;
  atclient_init(&atclient);

  const char *atsign = ATSIGN;

  if ((ret = atclient_utils_find_atserver_address(ROOT_HOST, ROOT_PORT, atsign, &atserver_host, &atserver_port)) !=
      0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "Failed to find atserver address\n");
    goto exit;
  }

  if ((ret = atclient_pkam_authenticate(&atclient, atserver_host, atserver_port, &atkeys, ATSIGN)) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "Failed to authenticate\n");
    goto exit;
  } else {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_DEBUG, "Authenticated\n");
  }

  goto exit;

exit: {
  atclient_atkeys_file_free(&atkeys_file);
  atclient_atkeys_free(&atkeys);
  atclient_free(&atclient);
  free(atserver_host);
  return 0;
}
}