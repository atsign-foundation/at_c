#include <atclient/atclient.h>
#include <atclient/atkeysfile.h>
#include <atlogger/atlogger.h>
#include <stdio.h>

#define ROOT_HOST "root.atsign.org"
#define ROOT_PORT 64

#define ATKEYSFILE_PATH "/home/realvarx/.atsign/keys/@expensiveferret_key.atKeys"
#define ATSIGN "@expensiveferret"

#define TAG "pkam_authenticate"

int main(int argc, char **argv) {
  int ret = 1;

  atlogger_set_logging_level(ATLOGGER_LOGGING_LEVEL_INFO);

  // 1. init atkeys

  // 1a. read `atkeysfile` struct
  atclient_atkeysfile atkeysfile;
  atclient_atkeysfile_init(&atkeysfile);
  ret = atclient_atkeysfile_read(&atkeysfile, ATKEYSFILE_PATH);
  // printf("atkeysfile_read_code: %d\n", ret);
  if (ret != 0) {
    goto exit;
  }
  atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_INFO, "atclient_atkeys_file_read: %d\n", ret);

  // 1b. populate `atkeys` struct
  atclient_atkeys atkeys;
  atclient_atkeys_init(&atkeys);
  ret = atclient_atkeys_populate_from_atkeysfile(&atkeys, atkeysfile);
  // printf("atkeys_populate_code: %d\n", ret);
  if (ret != 0) {
    goto exit;
  }
  atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_INFO, "atclient_atkeys_populate_from_atkeysfile: %d\n", ret);

  // 2. pkam auth
  atclient atclient;
  atclient_init(&atclient);
  
  atclient_connection root_conn;
  atclient_connection_init(&root_conn);
  atclient_connection_connect(&root_conn, "root.atsign.org", 64);

  atclient_atsign atsign;
  atclient_atsign_init(&atsign, ATSIGN);

  if ((ret = atclient_pkam_authenticate(&atclient, &root_conn, &atkeys, ATSIGN)) != 0) {
    atclient_atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "Failed to authenticate\n");
    goto exit;
  } else {
    atclient_atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_DEBUG, "Authenticated\n");
  }

  goto exit;

exit: {
  atclient_atkeysfile_free(&atkeysfile);
  atclient_atkeys_free(&atkeys);
  atclient_free(&atclient);
  return 0;
}
}