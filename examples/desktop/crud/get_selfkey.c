#include <atclient/atclient.h>
#include <atclient/atkey.h>
#include <atclient/constants.h>
#include <atclient/metadata.h>
#include <atlogger/atlogger.h>
#include <string.h>
#include <stdlib.h>

// publickey

#define TAG "Debug"

// #define ATSIGN "@jeremy_0"
#define ATSIGN "@soccer0"
#define ATKEYS_FILE_PATH "/Users/jeremytubongbanua/.atsign/keys/@soccer0_key.atKeys"

#define ATCLIENT_LOGGING_LEVEL ATLOGGER_LOGGING_LEVEL_DEBUG

#define ROOT_HOST "root.atsign.org"
#define ROOT_PORT 64

#define ATKEY_NAME "test"
#define ATKEY_NAMESPACE "dart_playground"
#define ATKEY_SHAREDBY "@soccer0"

int main() {
  int ret = 1;

  atlogger_set_logging_level(ATLOGGER_LOGGING_LEVEL_DEBUG);

  char *atserver_host = NULL;
  int atserver_port = -1;

  const size_t valuelen = 1024;
  char value[valuelen];
  memset(value, 0, valuelen);
  size_t valueolen = 0;

  atclient atclient;
  atclient_init(&atclient);

  const char *atsign = ATSIGN;

  atclient_atkey atkey;
  atclient_atkey_init(&atkey);

  atclient_atkeys atkeys;
  atclient_atkeys_init(&atkeys);
  atclient_atkeys_populate_from_path(&atkeys, ATKEYS_FILE_PATH);

  atclient_pkam_authenticate_options options;
  atclient_pkam_authenticate_options_init(&options);

  char *atkeystr = NULL;

  if ((ret = atclient_pkam_authenticate(&atclient, atsign, &atkeys, &options)) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "Failed to authenticate\n");
    goto exit;
  } else {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_DEBUG, "Successfully authenticated!\n");
  }

  if ((ret = atclient_atkey_create_self_key(&atkey, ATKEY_NAME, atsign, ATKEY_NAMESPACE)) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "Failed to create public key\n");
    goto exit;
  } else {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_DEBUG, "Created self key\n");
  }

  if ((ret = atclient_atkey_to_string(&atkey, &atkeystr)) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "Failed to convert to string\n");
    goto exit;
  }
  const size_t atkeystrlen = strlen(atkeystr);

  atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_DEBUG, "atkeystr.str (%lu): \"%.*s\"\n", atkeystrlen, (int)(atkeystrlen),
               atkeystr);

  ret = atclient_get_self_key(&atclient, &atkey, &value, NULL);
  if (ret != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "Failed to get self key");
    goto exit;
  }

  atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_INFO, "value.str (%lu): \"%.*s\"\n", valueolen, (int)valueolen, value);

  ret = 0;
  goto exit;
exit: {
  atclient_atkey_free(&atkey);
  atclient_atkeys_free(&atkeys);
  atclient_free(&atclient);
  atclient_pkam_authenticate_options_free(&options);
  free(atkeystr);
  return ret;
}
}
