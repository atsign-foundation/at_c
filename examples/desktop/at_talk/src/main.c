#include <atchops/aes.h>
#include <atchops/aesctr.h>
#include <atchops/base64.h>
#include <atchops/iv.h>
#include <atclient/atclient.h>
#include <atclient/atclient_utils.h>
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

pthread_mutex_t client_mutex;
pthread_mutex_t monitor_mutex;

typedef struct pthread_args_1 {
  atclient *monitor;
  atclient *ctx;
  const char *atserver_host;
  const int atserver_port;
  atclient_atkeys *atkeys;
  const char *from_atsign;
} pthread_args_1;

static int parse_args(int argc, char **argv, char **from_atsign, char **to_atsign);

static int reconnect_clients(atclient *monitor, atclient *ctx, const char *atserver_host, const int atserver_port,
                             atclient_atkeys *atkeys, const char *from_atsign);

static void *monitor_handler(void *xargs);

int main(int argc, char *argv[]) {
  int ret = 1;

  atlogger_set_logging_level(ATLOGGER_LOGGING_LEVEL_DEBUG);
  // atlogger_set_logging_level(ATLOGGER_LOGGING_LEVEL_WARN);

  char *from_atsign = NULL; // free later
  char *to_atsign = NULL;   // free later

  char *atserver_host = NULL; // free later
  int atserver_port = 0;

  atclient_atkeys atkeys; // free later
  atclient_atkeys_init(&atkeys);

  atclient atclient1; // free later
  atclient_init(&atclient1);

  atclient monitor; // free later
  atclient_init(&monitor);

  pthread_t tid;

  pthread_mutex_init(&client_mutex, NULL);
  pthread_mutex_init(&monitor_mutex, NULL);

  printf("Setup (1/3) .. ");

  /*
   * 1. Parse args to get `-f` and `-t` atSigns
   */
  if ((ret = parse_args(argc, argv, &from_atsign, &to_atsign)) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "\nFailed to parse args: %d\n", ret);
    goto exit;
  }

  /*
   * 2. Populate atkeys from homedir
   */
  if ((ret = atclient_utils_populate_atkeys_from_homedir(&atkeys, from_atsign)) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "\nFailed to set up atkeys: %d\n", ret);
    goto exit;
  }

  /*
   * 3. Find atserver address
   */
  if ((ret = atclient_utils_find_atserver_address(ROOT_HOST, ROOT_PORT, from_atsign, &atserver_host, &atserver_port)) !=
      0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "\nFailed to find atserver address: %d\n", ret);
    goto exit;
  }

  printf("(2/3) .. ");

  /*
   * 4. Authenticate client connection (for crud operations)
   */
  pthread_mutex_lock(&client_mutex);
  if ((ret = atclient_pkam_authenticate(&atclient1, atserver_host, atserver_port, &atkeys, from_atsign)) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "\natclient_pkam_authenticate: %d\n", ret);
    goto exit;
  }
  atclient_set_read_timeout(&atclient1, 500); // blocking read takes 50 ms to timeout
  pthread_mutex_unlock(&client_mutex);

  /*
   * 5. Start at talk receive messages thread
   */
  pthread_args_1 args = {&monitor, &atclient1, atserver_host, atserver_port, &atkeys, from_atsign};
  if ((ret = pthread_create(&tid, NULL, (void *)monitor_handler, &args)) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "\nFailed to create monitor_handler\n");
    return ret;
  }

  printf("(3/3).\n");

  /*
   * 6. Send at talk messages
   */
  char *line = NULL;
  size_t linelen = 0;
  size_t read;

  printf("%s%s%s: ", HBLU, from_atsign, reset);
  while ((read = getline(&line, &linelen, stdin)) != -1) {

    if (line[read - 1] == '\n') {
      line[read - 1] = '\0';
    }

    if (strlen(line) == 0) {
      continue;
    }

    atclient_notify_params params;
    atclient_notify_params_init(&params);

    atclient_atkey atkey;
    atclient_atkey_init(&atkey);

    atclient_atkey_create_sharedkey(&atkey, ATKEY_NAME, strlen(ATKEY_NAME), from_atsign, strlen(from_atsign), to_atsign,
                                    strlen(to_atsign), ATKEY_NAMESPACE, strlen(ATKEY_NAMESPACE));

    atclient_notify_params_create(&params, ATCLIENT_NOTIFY_OPERATION_UPDATE, &atkey, line, true);

    pthread_mutex_lock(&client_mutex);
    if ((ret = atclient_notify(&atclient1, &params, NULL)) != 0) {
      atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atclient_notify: %d\n", ret);
    }
    pthread_mutex_unlock(&client_mutex);

    // printf("%s%s%s: ", HBLU, from_atsign, reset);
  }

  ret = 0;
  goto exit;
exit: {
  atclient_free(&atclient1);
  atclient_free(&monitor);
  free(from_atsign);
  free(to_atsign);
  free(atserver_host);
  atclient_atkeys_free(&atkeys);
  pthread_mutex_destroy(&client_mutex);
  pthread_mutex_destroy(&monitor_mutex);
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

static void *monitor_handler(void *xargs) {
  int ret = 1;

  pthread_args_1 *args = (pthread_args_1 *)xargs;

  atclient *monitor = args->monitor;
  atclient *ctx = args->ctx;
  const char *atserver_host = args->atserver_host;
  const int atserver_port = args->atserver_port;
  atclient_atkeys *atkeys = args->atkeys;
  const char *from_atsign = args->from_atsign;

  pthread_mutex_lock(&monitor_mutex);
  if ((ret = atclient_monitor_pkam_authenticate(monitor, atserver_host, atserver_port, atkeys, from_atsign)) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atclient_pkam_authenticate: %d\n", ret);
    goto exit;
  }
  atclient_monitor_set_read_timeout(monitor, 500); // blocking read takes 1 second to timeout
  if ((ret = atclient_monitor_start(monitor, MONITOR_REGEX, strlen(MONITOR_REGEX))) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "Failed to start monitor: %d\n", ret);
    goto exit;
  }
  pthread_mutex_unlock(&monitor_mutex);

  int tries = 1;
  const size_t max_tries =
      20; // if we have 20 consecutive read failures, we should check if the connection is still alive.

  while (true) {
    atclient_monitor_message *message = NULL;
    pthread_mutex_lock(&monitor_mutex);
    pthread_mutex_lock(&client_mutex);
    ret = atclient_monitor_read(monitor, ctx, &message);
    pthread_mutex_unlock(&monitor_mutex);
    pthread_mutex_unlock(&client_mutex);

    switch (message->type) {
    case ATCLIENT_MONITOR_MESSAGE_TYPE_NOTIFICATION: {
      if (strcmp(message->notification.id, "-1") == 0) {
        // We received a stats notification. Ignore it.
        break;
      }
      if (atclient_atnotification_decryptedvalue_is_initialized(&(message->notification))) {
        atclient_atnotification *notification = &(message->notification);
        printf("\n%s%s%s: %s\n", HGRN, notification->from, reset, notification->decryptedvalue);
        // printf("%s%s%s: ", HBLU, from_atsign, reset);
      }
      tries = 1;
    }
    case ATCLIENT_MONITOR_ERROR_READ:
    case ATCLIENT_MONITOR_ERROR_PARSE: {
      if (tries >= max_tries) {
        atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_DEBUG,
                     "Failed to read a message for 30 consecutive reads, checking if connection is alive...\n", ret);
        pthread_mutex_lock(&monitor_mutex);
        pthread_mutex_lock(&client_mutex);
        if (atclient_monitor_is_connected(monitor) && atclient_is_connected(ctx)) {
          atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_DEBUG, "Connection is still alive.\n", ret);
          tries = 1;
        } else {
          atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_INFO, "Connection is not alive. Attempting reconnection...\n", ret);
          if ((ret = reconnect_clients(monitor, ctx, atserver_host, atserver_port, atkeys, from_atsign)) != 0) {
            atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "Failed to reconnect clients: %d\n", ret);
          } else {
            tries = 1;
            atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_INFO, "Reconnection successful.\n", ret);
          }
        }
        pthread_mutex_unlock(&monitor_mutex);
        pthread_mutex_unlock(&client_mutex);
      } else {
        tries++;
      }
      break;
    }
    default: {
      atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "Received message type: %d\n", message->type);
    }
    }

    atclient_monitor_message_free(message);
    usleep(100);
  }
  goto exit;

exit: { return NULL; }
}

static int reconnect_clients(atclient *monitor, atclient *ctx, const char *atserver_host, const int atserver_port,
                             atclient_atkeys *atkeys, const char *from_atsign) {
  int ret = 1;

  if ((ret = atclient_pkam_authenticate(ctx, atserver_host, atserver_port, atkeys, from_atsign)) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atclient_pkam_authenticate: %d\n", ret);
    return ret;
  }
  atclient_set_read_timeout(ctx, 500); // blocking read takes 0.5 second to timeout
  if ((ret = atclient_monitor_pkam_authenticate(monitor, atserver_host, atserver_port, atkeys, from_atsign)) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atclient_pkam_authenticate: %d\n", ret);
    return ret;
  }
  atclient_monitor_set_read_timeout(monitor, 500); // blocking read takes 0.5 second to timeout
  if ((ret = atclient_monitor_start(monitor, MONITOR_REGEX, strlen(MONITOR_REGEX))) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "Failed to start monitor: %d\n", ret);
    return ret;
  }
  if (ret == 0) {
    if (atclient_is_connected(ctx) && atclient_monitor_is_connected(monitor)) {
      atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_DEBUG, "Reconnection successful.\n", ret);
      ret = 0;
      return ret;
    } else {
      atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "Reconnection failed.\n", ret);
    }
  }
}
