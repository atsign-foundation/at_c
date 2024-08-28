#include <atclient/atclient.h>
#include <atclient/atkeysfile.h>
#include <atlogger/atlogger.h>
#include <stdio.h>

#define ROOT_HOST "root.atsign.org"
#define ROOT_PORT 64

#define ATKEYSFILE_PATH "/home/sitaram/.atsign/keys/@actingqualified_key.atKeys"
#define ATSIGN "@actingqualified"

#define TAG "pkam_authenticate"

int main(int argc, char **argv) {
  int ret = 1;

  atlogger_set_logging_level(ATLOGGER_LOGGING_LEVEL_INFO);

  // 1a. read `atkeysfile` struct
  atclient_atkeysfile atkeysfile;
  atclient_atkeysfile_init(&atkeysfile);
  ret = atclient_atkeysfile_read(&atkeysfile, ATKEYSFILE_PATH);
 
  if (ret != 0) {
    goto exit;
  }
  atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_INFO, "atclient_atkeys_file_read: %d\n", ret);

  // 1b. populate `atkeys` struct
  atclient_atkeys atkeys;
  atclient_atkeys_init(&atkeys);
  ret = atclient_atkeys_populate_from_atkeysfile(&atkeys, atkeysfile);
  
  atclient_pkam_authenticate_options options;
  atclient_pkam_authenticate_options_init(&options);

  if (ret != 0) {
    goto exit;
  }
  atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_INFO, "atclient_atkeys_populate_from_atkeysfile: %d\n", ret);

  // 2. pkam auth
  atclient atclient;
  atclient_init(&atclient);

  const char *atsign = ATSIGN;
  
  if ((ret = atclient_pkam_authenticate(&atclient, ATSIGN, &atkeys, &options)) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "Failed to authenticate\n");
    goto exit;
  } else {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_DEBUG, "Authenticated\n");
  }

  goto exit;

exit: {
  atclient_atkeysfile_free(&atkeysfile);
  atclient_atkeys_free(&atkeys);
  atclient_free(&atclient);
  atclient_pkam_authenticate_options_free(&options);
  return 0;
}
}