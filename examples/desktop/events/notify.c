#include <atclient/atclient.h>
#include <atclient/atclient_utils.h>
#include <atclient/atkey.h>
#include <atclient/atsign.h>
#include <atclient/constants.h>
#include <atclient/metadata.h>
#include <atclient/notify.h>
#include <atlogger/atlogger.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define TAG "Debug"

#define ATKEY_KEY "test"
#define ATKEY_NAMESPACE "dart_playground"
#define ATKEY_VALUE "test value"

#define ROOT_HOST "root.atsign.org"
#define ROOT_PORT 64

int main(int argc, char *argv[]) {
  int ret = 1;
  atlogger_set_logging_level(ATLOGGER_LOGGING_LEVEL_DEBUG);

  const char *atsign = "@soccer0";

  const size_t valuelen = 1024;
  char value[valuelen];
  memset(value, 0, sizeof(char) * valuelen);
  size_t valueolen = 0;

  char atkeys_path[1024];
  memset(atkeys_path, 0, sizeof(char) * 1024);

  atclient atclient;
  atclient_init(&atclient);

  char *atserver_host = NULL;
  int atserver_port = -1;

  atclient_atkey atkey;
  atclient_atkey_init(&atkey);

  atclient_atkeys atkeys;
  atclient_atkeys_init(&atkeys);

  char *atkeystr = NULL;

  atclient_notify_params notify_params;
  atclient_notify_params_init(&notify_params);

  const char *homedir;

  char *atsign_input = NULL;
  char *other_atsign_input = NULL;
  // allow input of -a and -o flags with get opts

  int c;
  while ((c = getopt(argc, argv, "a:o:")) != -1)
    switch (c) {
    case 'a':
      atsign_input = optarg;
      break;
    case 'o':
      other_atsign_input = optarg;
      break;
    }

  // print both atsign
  if (atsign_input == NULL || other_atsign_input == NULL) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "Please provide both atsigns with -a and -o flags\n");
    ret = 1;
    goto exit;
  }
  atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_INFO, "atsign_input: %s\n", atsign_input);
  atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_INFO, "other_atsign_input: %s\n", other_atsign_input);

  if ((ret = atclient_utils_find_atserver_address(ROOT_HOST, ROOT_PORT, atsign, &atserver_host,
                                                  &atserver_port)) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "Failed to find atserver address\n");
    goto exit;
  }

  if ((homedir = getenv("HOME")) == NULL) {
    printf("HOME not set\n");
    ret = 1;
    goto exit;
  }

  snprintf(atkeys_path, 1024, "%s/.atsign/keys/%s_key.atKeys", homedir, atsign_input);
  ret = atclient_atkeys_populate_from_path(&atkeys, atkeys_path);
  if (ret != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "Failed to populate atkeys\n");
    free(atserver_host);
    goto exit;
  }

  if ((ret = atclient_pkam_authenticate(&atclient, atserver_host, atserver_port, &atkeys, atsign)) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "Failed to authenticate\n");
    goto exit;
  }

  if ((ret = atclient_atkey_create_shared_key(&atkey, ATKEY_KEY, atsign_input, other_atsign_input, ATKEY_NAMESPACE)) !=
      0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "Failed to create public key\n");
    goto exit;
  }

  atclient_atkey_metadata_set_ccd(&atkey.metadata, true);

  if ((ret = atclient_atkey_to_string(&atkey, &atkeystr)) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "Failed to convert to string\n");
    goto exit;
  }
  const size_t atkeystrlen = strlen(atkeystr);

  atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_DEBUG, "atkeystr.str (%lu): \"%.*s\"\n", atkeystrlen, (int)atkeystrlen,
               atkeystr);

  if((ret = atclient_notify_params_set_atkey(&notify_params, &atkey)) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "Failed to set atkey\n");
    goto exit;
  }

  if((ret = atclient_notify_params_set_value(&notify_params, ATKEY_VALUE)) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "Failed to set value\n");
    goto exit;
  }

  if((ret = atclient_notify_params_set_operation(&notify_params, ATCLIENT_NOTIFY_OPERATION_UPDATE)) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "Failed to set operation\n");
    goto exit;
  }

  if ((ret = atclient_notify(&atclient, &notify_params, NULL)) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "Failed to notify\n");
    goto exit;
  }

  atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_DEBUG, "Sent notification.\n");

  ret = 0;
  goto exit;
exit: {
  atclient_atkeys_free(&atkeys);
  atclient_atkey_free(&atkey);
  free(atserver_host);
  atclient_free(&atclient);
  free(atkeystr);
  return ret;
}
}
