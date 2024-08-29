#include <atclient/atclient.h>
#include <atclient/atkeys_file.h>
#include <atlogger/atlogger.h>
#include <stdio.h>

#define ROOT_HOST "root.atsign.org"
#define ROOT_PORT 64

#define ATKEYS_FILE_PATH "/home/sitaram/.atsign/keys/@actingqualified_key.atKeys"
#define ATSIGN "@actingqualified"

#define TAG "pkam_authenticate"

int main(int argc, char **argv) {
  int ret = 1;

  atlogger_set_logging_level(ATLOGGER_LOGGING_LEVEL_INFO);

  // 1a. read `atkeys_file` struct
  atclient_atkeys_file atkeys_file;
  atclient_atkeys_file_init(&atkeys_file);

  // 1b. populate `atkeys` struct
  atclient_atkeys atkeys;
  atclient_atkeys_init(&atkeys);

  atclient_pkam_authenticate_options options;
  atclient_pkam_authenticate_options_init(&options);

  // 2. pkam auth
  atclient atclient;
  atclient_init(&atclient);

  ret = atclient_atkeys_file_read(&atkeys_file, ATKEYS_FILE_PATH);
  if (ret != 0) {
    goto exit;
  }
  atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_INFO, "atclient_atkeys_file_read: %d\n", ret);

  ret = atclient_atkeys_populate_from_atkeys_file(&atkeys, &atkeys_file);
  if (ret != 0) {
    goto exit;
  }
  atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_INFO, "atclient_atkeys_populate_from_atkeys_file: %d\n", ret);

  const char *atsign = ATSIGN;

  if ((ret = atclient_pkam_authenticate(&atclient, ATSIGN, &atkeys, &options)) != 0) {
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
  atclient_pkam_authenticate_options_free(&options);
  return 0;
}
}