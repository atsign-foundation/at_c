#include <atclient/atclient.h>
#include <atclient/atkey.h>
#include <atclient/atsign.h>
#include <atclient/constants.h>
#include <atclient/metadata.h>
#include <atclient/monitor.h>
#include <atlogger/atlogger.h>
#include <pthread.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define TAG "Debug"

#define ROOT_HOST "vip.ve.atsign.zone"
#define ROOT_PORT 64

static void *heartbeat_handler(void *monitor_connection);

int main(int argc, char *argv[]) {
  int ret = 1;
  atclient_atlogger_set_logging_level(ATLOGGER_LOGGING_LEVEL_DEBUG);

  char *atsign_input = NULL;
  // allow input of -a and -o flags with get opts

  int c;
  while ((c = getopt(argc, argv, "a:")) != -1)
    switch (c) {
    case 'a':
      atsign_input = optarg;
      break;
    }

  // print atsign
  printf("atsign_input: %s\n", atsign_input);
  if (atsign_input == NULL) {
    atclient_atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "Please provide both atsigns with -a and -o flags\n");
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
  atclient_connection_connect(&root_connection, ROOT_HOST, ROOT_PORT);

  atclient_atsign atsign;
  atclient_atsign_init(&atsign, atsign_input);

  atclient_atkeys atkeys;
  atclient_atkeys_init(&atkeys);
  const char *homedir;

  if ((homedir = getenv("HOME")) == NULL) {
    printf("HOME not set\n");
    return 1;
  }
  char atkeys_path[1024];
  snprintf(atkeys_path, 1024, "%s/.atsign/keys/%s_key.atKeys", homedir, atsign_input);

  atclient_atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_INFO, "Reading atkeys file: %s\n", atkeys_path);
  atclient_atkeys_populate_from_path(&atkeys, atkeys_path);

  printf("Starting monitor\n");
  struct atclient monitor_ctx;
  atclient_monitor_init(&monitor_ctx, atsign, atkeys);
  ret = atclient_start_monitor(&monitor_ctx, ROOT_HOST, ROOT_PORT, "");
  if (ret != 0) {
    atclient_atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "Monitor crashed\n");
    goto exit;
  }
  printf("Monitor started!\n");

  printf("Starting heartbeat\n");
  pthread_t tid;
  ret = pthread_create(&tid, NULL, heartbeat_handler, &monitor_ctx);
  if (ret != 0) {
    atclient_atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "Failed to create heartbeat_handler\n");
    goto exit;
  }
  printf("Heartbeat started!\n");
  if (ret < 0) {
    goto exit;
  }

  if ((ret = atclient_pkam_authenticate(&atclient, &root_connection, atkeys, atsign.atsign, strlen(atsign.atsign))) !=
      0) {
    atclient_atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "Failed to authenticate\n");
    goto exit;
  }

  printf("Starting main monitor loop\n");
  while (true) {
    atclient_monitor_message message;
    int mon_ret = atclient_read_monitor(&monitor_ctx, &message);
    if (mon_ret != 0) {
      atclient_atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "Failed to read monitor message\n");
      continue;
    }

    switch (message.type) {
    case MMT_none:
      atclient_atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_DEBUG, "Message type: none\n");
      break;
    case MMT_notification:
      atclient_atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_DEBUG, "Message type: notification\n");
      atclient_atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_DEBUG, "Message id: %s\n", message.notification.id);
      break;
    case MMT_data_response:
      atclient_atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_DEBUG, "Message type: data\n");
      atclient_atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_DEBUG, "Message body: %s\n", message.data_response);
      break;
    case MMT_error_response:
      atclient_atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_DEBUG, "Message type: error\n");
      atclient_atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_DEBUG, "Message body: %s\n", message.error_response);
      break;
    }
  }
  printf("Main monitor loop complete!\n");

  ret = 0;
  goto exit;
exit: {
  if (pthread_cancel(tid) != 0) {
    atclient_atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "Failed to cancel heartbeat_handler\n");
  }
  atclient_atkeys_free(&atkeys);
  atclient_atsign_free(&atsign);
  atclient_free(&atclient);
  atclient_connection_free(&root_connection);
  return ret;
}
}

static void *heartbeat_handler(void *monitor_connection) {
  atclient *connection = (atclient *)monitor_connection;
  atclient_atlogger_log("Heartbeat_handler", ATLOGGER_LOGGING_LEVEL_INFO, "Starting heartbeat_handler\n");
  while (true) {
    sleep(30);
    atclient_atlogger_log("Heartbeat_handler", ATLOGGER_LOGGING_LEVEL_DEBUG, "Sending heartbeat\n");
    atclient_send_heartbeat(connection);
  };
}
