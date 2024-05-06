#include <atclient/atclient.h>
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

#define ROOT_HOST "vip.ve.atsign.zone"
#define ROOT_PORT 64

int main(int argc, char *argv[]) {
  int ret = 1;
  atlogger_set_logging_level(ATLOGGER_LOGGING_LEVEL_DEBUG);

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
  printf("atsign_input: %s\n", atsign_input);
  printf("other_atsign_input: %s\n", other_atsign_input);
  if (atsign_input == NULL || other_atsign_input == NULL) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "Please provide both atsigns with -a and -o flags\n");
    return 1;
  }

  const size_t valuelen = 1024;
  char value[valuelen];
  memset(value, 0, sizeof(char) * valuelen);
  size_t valueolen = 0;

  atclient atclient;
  atclient_init(&atclient);

  atclient_connection root_connection;
  atclient_connection_init(&root_connection);
  ret = atclient_connection_connect(&root_connection, ROOT_HOST, ROOT_PORT);
  if (ret != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "Failed to connect to root\n");
    atclient_connection_free(&root_connection);
    goto exit;
  }

  atclient_atsign atsign;
  atclient_atsign_init(&atsign, atsign_input);

  atclient_atkey atkey;
  atclient_atkey_init(&atkey);

  atclient_atkeys atkeys;
  atclient_atkeys_init(&atkeys);
  const char *homedir;

  if ((homedir = getenv("HOME")) == NULL) {
    printf("HOME not set\n");
    return 1;
  }

  char atkeys_path[1024];
  snprintf(atkeys_path, 1024, "%s/.atsign/keys/%s_key.atKeys", homedir, atsign_input);
  atclient_atkeys_populate_from_path(&atkeys, atkeys_path);

  atclient_atstr atkeystr;
  atclient_atstr_init(&atkeystr, ATCLIENT_ATKEY_FULL_LEN);

  if ((ret = atclient_pkam_authenticate(&atclient, &root_connection, &atkeys, atsign.atsign)) !=
      0) {
    atclient_connection_free(&root_connection);
    atclient_atsign_free(&atsign);
    atclient_atkey_free(&atkey);
    atclient_atkeys_free(&atkeys);
    atclient_atstr_free(&atkeystr);

    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "Failed to authenticate");
    goto exit;
  }

  if ((ret = atclient_atkey_create_sharedkey(&atkey, ATKEY_KEY, strlen(ATKEY_KEY), atsign_input, strlen(atsign_input),
                                             other_atsign_input, strlen(other_atsign_input), ATKEY_NAMESPACE,
                                             strlen(ATKEY_NAMESPACE))) != 0) {
    atclient_connection_free(&root_connection);
    atclient_atsign_free(&atsign);
    atclient_atkey_free(&atkey);
    atclient_atkeys_free(&atkeys);
    atclient_atstr_free(&atkeystr);
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "Failed to create public key");
    goto exit;
  }

  atclient_atkey_metadata_set_ccd(&atkey.metadata, true);

  if ((ret = atclient_atkey_to_string(&atkey, atkeystr.str, atkeystr.size, &atkeystr.len)) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "Failed to convert to string");
    goto exit;
  }

  atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_DEBUG, "atkeystr.str (%lu): \"%.*s\"\n", atkeystr.len,
                        (int)atkeystr.len, atkeystr.str);

  atclient_notify_params notify_params;
  atclient_notify_params_init(&notify_params);

  notify_params.key = atkey;
  notify_params.value = ATKEY_VALUE;
  notify_params.operation = NO_update;

  if ((ret = atclient_notify(&atclient, &notify_params)) != 0) {
    atclient_connection_free(&root_connection);
    atclient_atsign_free(&atsign);
    atclient_atkey_free(&atkey);
    atclient_atkeys_free(&atkeys);
    atclient_atstr_free(&atkeystr);
    atclient_notify_params_free(&notify_params);

    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "Failed to notify");
    goto exit;
  }

  atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_DEBUG, "Sent notification");

  ret = 0;
  goto exit;
exit: { return ret; }
}
