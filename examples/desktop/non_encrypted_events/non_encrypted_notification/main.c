#include <atlogger/atlogger.h>
#include <atclient/notify.h>
#include <atclient/atclient.h>

#define TAG "main"

#define ATSIGN "@12snowboating"
#define KEYS_PATH "/home/jeremy/.atsign/keys/@12snowboating_key.atKeys"

int main() {
  int ret = 1;

  atlogger_set_logging_level(ATLOGGER_LOGGING_LEVEL_DEBUG);

  atclient main_client;
  atclient_init(&main_client);

  atclient_atkeys atkeys;
  atclient_atkeys_init(&atkeys);

  atclient_atkey atkey;
  atclient_atkey_init(&atkey);

  atclient_notify_params params;
  atclient_notify_params_init(&params);

  if((ret = atclient_atkeys_populate_from_path(&atkeys, KEYS_PATH)) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "Failed to populate atkeys from path\n");
    goto exit;
  }

  if((ret = atclient_pkam_authenticate(&main_client, ATSIGN, &atkeys, NULL, NULL)) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "Failed to authenticate connection\n");
    goto exit;
  }


  if((ret = atclient_atkey_create_shared_key(&atkey, "non_encrypted_notification", "@12snowboating", "@12alpaca", "test")) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "Failed to create shared key\n");
    goto exit;
  }

  if((ret = atclient_notify_params_set_atkey(&params, &atkey)) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "Failed to set atkey\n");
    goto exit;
  }

  if((ret = atclient_notify_params_set_value(&params, "Hello, World!")) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "Failed to set value\n");
    goto exit;
  }

  if((ret = atclient_notify_params_set_should_encrypt(&params, false)) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "Failed to set should_encrypt\n");
    goto exit;
  }

  // print params
  atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_INFO, "Params:\n");
  atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_INFO, "  atkey: %p\n", params.atkey);
  atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_INFO, "  value: %s\n", params.value);
  atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_INFO, "  should_encrypt: %d\n", params.should_encrypt);


  if((ret = atclient_notify(&main_client, &params, NULL)) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "Failed to send notification\n");
    goto exit;
  }

  ret = 0;

exit: { return ret; }
}