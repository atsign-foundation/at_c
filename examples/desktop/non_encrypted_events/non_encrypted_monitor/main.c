#include <atlogger/atlogger.h>
#include <atclient/atclient.h>
#include <atclient/monitor.h>

#define ATSIGN "@12alpaca"
#define KEYS_PATH "/home/jeremy/.atsign/keys/@12alpaca_key.atKeys"

#define TAG "main"

int main() {
  int ret = 1;

  atlogger_set_logging_level(ATLOGGER_LOGGING_LEVEL_DEBUG);

  atclient main_client;
  atclient_init(&main_client);

  atclient monitor_client;
  atclient_init(&monitor_client);

  atclient_atkeys atkeys;
  atclient_atkeys_init(&atkeys);

  if((ret = atclient_atkeys_populate_from_path(&atkeys, KEYS_PATH)) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "Failed to populate atkeys from path\n");
    goto exit;
  }

  if((ret = atclient_pkam_authenticate(&main_client, ATSIGN, &atkeys, NULL, NULL)) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "Failed to authenticate connection\n");
    goto exit;
  }

  if((ret = atclient_monitor_pkam_authenticate(&monitor_client, ATSIGN, &atkeys, NULL)) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "Failed to authenticate monitor connection\n");
    goto exit;
  }

  if((ret = atclient_monitor_start(&monitor_client, ".*")) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "Failed to start monitor\n");
    goto exit;
  }

  while(1) {
    atclient_monitor_message message;
    atclient_monitor_message_init(&message);

    ret = atclient_monitor_read(&monitor_client, &main_client, &message, NULL);

    if(message.type == ATCLIENT_MONITOR_MESSAGE_TYPE_NOTIFICATION) {
      if (atclient_atnotification_is_value_initialized(message.notification)) {
        atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_INFO, "Received notification: \"%s\"\n", message.notification->value);
      }
    }

    atclient_monitor_message_free(&message);
  }
  

  ret = 0;

exit: { return ret; }
}