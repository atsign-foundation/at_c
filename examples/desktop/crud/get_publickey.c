#include <atclient/atclient.h>
#include <atclient/atkey.h>
#include <atclient/constants.h>
#include <atclient/metadata.h>
#include <atlogger/atlogger.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// publickey

#define TAG "Debug"

// #define ATSIGN "@jeremy_0"
#define ATSIGN "@qt_thermostat"
#define ATKEYS_FILE_PATH "/Users/jeremytubongbanua/.atsign/keys/@qt_thermostat_key.atKeys"

#define ATCLIENT_LOGGING_LEVEL ATLOGGER_LOGGING_LEVEL_DEBUG

#define ROOT_HOST "root.atsign.org"
#define ROOT_PORT 64

#define ATKEY_NAME "publickey"
#define ATKEY_SHAREDBY "@colin"

int main() {
  int ret = 1;

  atlogger_set_logging_level(ATCLIENT_LOGGING_LEVEL);

  const size_t valuelen = 4096;
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

  char *atserver_host = NULL;
  int atserver_port = -1;

  char *metadatajsonstr = NULL;

  if ((ret = atclient_pkam_authenticate(&atclient, atsign, &atkeys, &options)) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "Failed to authenticate");
    goto exit;
  }

  if ((ret = atclient_atkey_create_public_key(&atkey, ATKEY_NAME, ATKEY_SHAREDBY, NULL)) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "Failed to create public key");
    goto exit;
  }

  if ((ret = atclient_atkey_to_string(&atkey, &atkeystr)) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "Failed to convert to string");
    goto exit;
  }
  const size_t atkeystrlen = strlen(atkeystr);

  atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_DEBUG, "atkeystr.str (%lu): \"%.*s\"\n", atkeystrlen, (int)atkeystrlen,
               atkeystr);

  if ((ret = atclient_get_public_key(&atclient, &atkey, value, NULL)) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "Failed to get public key");
    goto exit;
  }

  atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_DEBUG, "Data: \"%.*s\"\n", (int)valueolen, value);

  if ((ret = atclient_atkey_metadata_to_json_str(&atkey.metadata, &metadatajsonstr)) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "Failed to convert metadata to json string");
    goto exit;
  }

  atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_DEBUG, "Metadata: \"%.*s\"\n", metadatajsonstr);

  ret = 0;
  goto exit;
exit: {
  atclient_atkeys_free(&atkeys);
  atclient_atkey_free(&atkey);
  atclient_free(&atclient);
  atclient_pkam_authenticate_options_free(&options);
  free(atkeystr);
  return ret;
}
}
