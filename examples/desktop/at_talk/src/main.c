#include <atchops/aes.h>
#include <atchops/aesctr.h>
#include <atchops/base64.h>
#include <atchops/iv.h>
#include <atclient/atclient.h>
#include <atclient/atkeysfile.h>
#include <atclient/atsign.h>
#include <atclient/constants.h>
#include <atclient/encryption_key_helpers.h>
#include <atclient/monitor.h>
#include <atclient/notify.h>
#include <atlogger/atlogger.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define ROOT_HOST "root.atsign.org"
#define ROOT_PORT 64

#define ATKEY_NAME "at_talk"
#define ATKEY_NAMESPACE "at_talk"

#define MONITOR_REGEX ".*"

#define TAG "at_talk"

static int parse_args(int argc, char **argv, char **from_atsign, char **to_atsign);
static int get_atkeys_path(const char *atsign, const size_t atsignlen, char **atkeyspath);
static void *monitor_handler(atclient *atclient2);
static int attalk_send_message(atclient *ctx, const char *recipient_atsign, const char *message,
                               const size_t messagelen);
static void attalk_recv_message(atclient_monitor_message *message);

int main(int argc, char **argv) {
  int ret = 0;

  atlogger_set_logging_level(ATLOGGER_LOGGING_LEVEL_DEBUG);

  char *atkeyspath1 = NULL;

  char *from_atsign = NULL;
  char *to_atsign = NULL;

  atclient_atkeys atkeys1;
  atclient_atkeys_init(&atkeys1);

  atclient_connection root_conn;
  atclient_connection_init(&root_conn);

  atclient atclient1;
  atclient_init(&atclient1);

  atclient monitor;
  atclient_init(&monitor);

  pthread_t tid;

  if ((ret = parse_args(argc, argv, &from_atsign, &to_atsign)) != 0) {
    printf("Issue with parsing arguments\n");
    goto exit;
  }

  if ((ret = get_atkeys_path(from_atsign, strlen(from_atsign), &atkeyspath1)) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "Issue with getting atkeys path for %s\n", from_atsign);
    goto exit;
  }

  if ((ret = atclient_atkeys_populate_from_path(&atkeys1, atkeyspath1)) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atclient_atkeys_file_read: %d\n", ret);
    goto exit;
  }

  if ((ret = atclient_connection_connect(&root_conn, ROOT_HOST, ROOT_PORT)) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atclient_connection_connect: %d\n", ret);
    goto exit;
  }

  if ((ret = atclient_pkam_authenticate(&atclient1, &root_conn, &atkeys1, from_atsign)) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atclient_pkam_authenticate: %d\n", ret);
    goto exit;
  }

  if ((ret = atclient_monitor_pkam_authenticate(&monitor, &root_conn, &atkeys1, from_atsign)) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atclient_pkam_authenticate: %d\n", ret);
    goto exit;
  }

  ret = pthread_create(&tid, NULL, monitor_handler, &monitor);
  if (ret != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "Failed to create monitor_handler\n");
    return ret;
  }

  char *line = NULL;
  size_t linelen = 0;
  size_t read;

  while ((read = getline(&line, &linelen, stdin)) != -1) {

    if (line[read - 1] == '\n') {
      line[read - 1] = '\0';
    }

    ret = attalk_send_message(&atclient1, to_atsign, line, linelen);
  }

  ret = 0;
  goto exit;
exit: {
  // free everything
  atclient_atkeys_free(&atkeys1);
  atclient_free(&atclient1);
  atclient_free(&monitor);
  atclient_connection_free(&root_conn);
  free(atkeyspath1);
  ret = pthread_cancel(tid);
  atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_INFO, "pthread exit: %d\n", ret);
  return ret;
}
}

static int parse_args(int argc, char **argv, char **from_atsign, char **to_atsign) {
  if (argc < 5) {
    fprintf(stderr, "Usage: %s -f <from_atsign> -t <to_atsign>\n", argv[0]);
    return 1;
  }

  int c;
  while ((c = getopt(argc, argv, "f:t:")) != -1) {
    switch (c) {
    case 'f':
      *from_atsign = optarg;
      break;
    case 't':
      *to_atsign = optarg;
      break;
    default:
      fprintf(stderr, "Usage: %s -f <from_atsign> -t <to_atsign>\n", argv[0]);
      return 1;
    }
  }

  if (*from_atsign == NULL || *to_atsign == NULL) {
    fprintf(stderr, "Usage: %s -f <from_atsign> -t <to_atsign>\n", argv[0]);
    return 1;
  }
  return 0;
}
static int get_atkeys_path(const char *atsign, const size_t atsignlen, char **atkeyspath) {
  // get home path
  char *home = getenv("HOME");
  if (home == NULL) {
    return 1;
  }

  // allocate memory for atkeys path
  char *atkeys_path = (char *)malloc(strlen(home) + strlen("/.atsign/keys/") + atsignlen + strlen("_key.atkeys") + 1);
  if (atkeys_path == NULL) {
    return 1;
  }

  // create atkeys path
  sprintf(atkeys_path, "%s/.atsign/keys/%.*s_key.atkeys", home, (int)atsignlen, atsign);

  *atkeyspath = atkeys_path;
  return 0;
}

static void *monitor_handler(atclient *atclient2) {
  int ret = 0;

  atclient_monitor_message *message;

  if ((ret = atclient_monitor_start(atclient2, MONITOR_REGEX, strlen(MONITOR_REGEX))) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "Failed to start monitor: %d\n", ret);
    goto exit;
  }

  bool loop = true;

  while (loop) {
    ret = atclient_monitor_read(atclient2, atclient2, &message);
    if (ret != 0) {
      atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atclient_monitor_for_notification: %d\n", ret);
      loop = false;
      break;
    }

    attalk_recv_message(message);
  }

exit: {
  atclient_monitor_message_free(message);
  return NULL;
}
}

static int attalk_send_message(atclient *ctx, const char *recipient_atsign, const char *message,
                               const size_t messagelen) {
  int ret = 1;

  atclient_notify_params params;
  atclient_notify_params_init(&params);

  atclient_atkey atkey;
  atclient_atkey_init(&atkey);

  if ((ret = atclient_atkey_create_sharedkey(&atkey, ATKEY_NAME, strlen(ATKEY_NAME), ctx->atsign.atsign,
                                             strlen(ctx->atsign.atsign), recipient_atsign, strlen(recipient_atsign),
                                             ATKEY_NAMESPACE, strlen(ATKEY_NAMESPACE))) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "Failed to create atkey: %d\n", ret);
    goto exit;
  }

  atclient_notify_params_create(&params, ATCLIENT_NOTIFY_OPERATION_UPDATE, &atkey, message, true);

  if ((ret = atclient_notify(ctx, &params, NULL)) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "Failed to notify: %d\n", ret);
    goto exit;
  }

  ret = 0;
  goto exit;
exit: { return ret; }
}

static void attalk_recv_message(atclient_monitor_message *message) {
  int ret = 1;

  switch (message->type) {
  case ATCLIENT_MONITOR_MESSAGE_TYPE_NONE: {
    break;
  }
  case ATCLIENT_MONITOR_MESSAGE_TYPE_DATA_RESPONSE: {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_INFO, "Received message: %s\n", message->data_response);
    break;
  }
  case ATCLIENT_MONITOR_MESSAGE_TYPE_ERROR_RESPONSE: {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "Received error: %s\n", message->error_response);
    break;
  }
  case ATCLIENT_MONITOR_MESSAGE_TYPE_NOTIFICATION: {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_INFO, "Received notification: %s\n", message->notification.decryptedvalue);
    break;
  }
  default: {
    break;
  }
  }
}