#include <atclient/atclient.h>
#include <atclient/atkeys_file.h>
#include <atlogger/atlogger.h>
#include <stdio.h>

#define ROOT_HOST "root.atsign.org"
#define ROOT_PORT 64

#define ATKEYS_FILE_PATH "/Users/jeremytubongbanua/.atsign/keys/@smoothalligator_key.atKeys"
#define ATSIGN "@smoothalligator"

#define TAG "pkam_authenticate"

int main(int argc, char **argv) {
  int ret = 1;

  atlogger_set_logging_level(ATLOGGER_LOGGING_LEVEL_DEBUG);

  atclient_atkeys_file atkeys_file;
  atclient_atkeysfile_init(&atkeys_file);

  atclient_atkeys atkeys;
  atclient_atkeys_init(&atkeys);

  atclient atclient;
  atclient_init(&atclient);

  if ((ret = atclient_atkeysfile_from_path(&atkeys_file, ATKEYS_FILE_PATH)) != 0) {
    goto exit;
  }
  atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_INFO, "atclient_atkeysfile_read: %d\n", ret);

  if ((ret = atclient_atkeys_populate_from_atkeys_file(&atkeys, &atkeys_file)) != 0) {
    goto exit;
  }
  atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_INFO, "atclient_atkeys_populate_from_atkeys_file: %d\n", ret);

  const char *atsign = ATSIGN;

  if ((ret = atclient_pkam_authenticate(&atclient, ATSIGN, &atkeys, NULL)) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "Failed to authenticate\n");
    goto exit;
  } else {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_DEBUG, "Authenticated\n");
  }

  goto exit;

exit: {
  atclient_atkeysfile_free(&atkeys_file);
  atclient_atkeys_free(&atkeys);
  atclient_free(&atclient);
  return 0;
}
}
