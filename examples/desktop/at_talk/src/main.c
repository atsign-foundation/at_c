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
#include <atclient/constants.h>
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
static int attalk_recv_message(atclient *monitor, char **messageptr, char **sender_atsign);

int main(int argc, char **argv) {
  int ret = 0;

  // atlogger_set_logging_level(ATLOGGER_LOGGING_LEVEL_DEBUG);
  atlogger_set_logging_level(ATLOGGER_LOGGING_LEVEL_WARN);

  char *atkeyspath1 = NULL;

  char *from_atsign = NULL;
  char *to_atsign = NULL;

  char *atserver_host = NULL;
  int atserver_port = -1;

  atclient_atkeys atkeys1;
  atclient_atkeys_init(&atkeys1);

  atclient atclient1;
  atclient_init(&atclient1);

  atclient monitor;
  atclient_init(&monitor);

  pthread_t tid;

  printf("Setup (1/3) .. ");

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


  if((ret = atclient_find_atserver_address(ROOT_HOST, ROOT_PORT, from_atsign, &atserver_host, &atserver_port)) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atclient_find_atserver_address: %d\n", ret);
    goto exit;
  }

    printf("(2/3) .. ");


  if ((ret = atclient_pkam_authenticate(&atclient1, atserver_host, atserver_port, &atkeys1, from_atsign)) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atclient_pkam_authenticate: %d\n", ret);
    goto exit;
  }

  if ((ret = atclient_monitor_pkam_authenticate(&monitor, atserver_host, atserver_port, &atkeys1, from_atsign)) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atclient_pkam_authenticate: %d\n", ret);
    goto exit;
  }

  ret = pthread_create(&tid, NULL,  (void *) monitor_handler, &monitor);
  if (ret != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "Failed to create monitor_handler\n");
    return ret;
  }

  printf("(3/3).\n");

  char *line = NULL;
  size_t linelen = 0;
  size_t read;

  printf("%s%s%s -> ", HBLU, from_atsign, reset);
  while ((read = getline(&line, &linelen, stdin)) != -1) {

    if (line[read - 1] == '\n') {
      line[read - 1] = '\0';
    }

    ret = attalk_send_message(&atclient1, to_atsign, line, linelen);
    printf("%s%s%s -> ", HBLU, from_atsign, reset);
  }

  ret = 0;
  goto exit;
exit: {
  // free everything
  atclient_atkeys_free(&atkeys1);
  atclient_free(&atclient1);
  atclient_free(&monitor);
  free(atserver_host);
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

  if ((ret = atclient_monitor_start(atclient2, MONITOR_REGEX, strlen(MONITOR_REGEX))) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "Failed to start monitor: %d\n", ret);
    goto exit;
  }

  bool loop = true;

  while (loop) {
    char *messageptr = NULL;
    char *sender_atsign = NULL;
    attalk_recv_message(atclient2, &messageptr, &sender_atsign);
    if (messageptr != NULL) {
      printf("\n%s%s%s: %s\n", HMAG, sender_atsign, reset, messageptr);
      free(messageptr);
      free(sender_atsign);
    }
  }
  goto exit;

exit: { return NULL; }
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

static int attalk_recv_message(atclient *monitor, char **messageptr, char **sender_atsign) {
  int ret = 1;

  atclient_monitor_message *message = NULL;

  if ((ret = atclient_monitor_read(monitor, monitor, &message)) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atclient_monitor_for_notification: %d\n", ret);
    goto exit;
  }

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
    // if key does not contain ATKEY_NAMESPACE, skip
    atclient_atkey atkey;
    atclient_atkey_init(&atkey);
    atclient_atkey_from_string(&atkey, message->notification.key, strlen(message->notification.key));

    if (strcmp(atkey.namespacestr.str, ATKEY_NAMESPACE) == 0 && strcmp(atkey.name.str, ATKEY_NAME) == 0) {
      // clear stdin
      *messageptr = strdup((char *) message->notification.decryptedvalue);
      *sender_atsign = strdup(message->notification.from);
      ret = 0;
    }
    atclient_atkey_free(&atkey);
    break;
  }
  default: {
    break;
  }
  }
  goto exit;
exit: {
  atclient_monitor_message_free(message);
  return ret;
}
}
