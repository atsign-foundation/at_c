#include <atchops/aes.h>
#include <atchops/aes_ctr.h>
#include <atchops/base64.h>
#include <atchops/iv.h>
#include <atclient/atclient.h>
#include <atclient/atclient_utils.h>
#include <atclient/atkeysfile.h>
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

#define ATKEY_NAME "attalk"
#define ATKEY_NAMESPACE "ai6bh"

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

#define READ_TIMEOUT 1000
#define MAX_RETRIES 5 // if we have 5 consecutive read failures, we should check if the connection is still alive.

static int parse_args(int argc, char **argv, char **from_atsign, char **to_atsign);

static int reconnect_clients(atclient *monitor, atclient *ctx, const char *atserver_host, const int atserver_port,
                             atclient_atkeys *atkeys, const char *from_atsign);

static void *monitor_handler(void *xargs);

int main(int argc, char *argv[]) {
  int ret = 1;

  // atlogger_set_logging_level(ATLOGGER_LOGGING_LEVEL_INFO);
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
  atclient_monitor_init(&monitor);

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
  atclient_set_read_timeout(&atclient1, READ_TIMEOUT); // blocking read takes 50 ms to timeout
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
    if (read > 1) {
      if (line[read - 1] == '\n') {
        line[read - 1] = '\0';
      }
    }

    if (strlen(line) == 0) {
      continue;
    }

    atclient_notify_params params;
    atclient_notify_params_init(&params);

    atclient_atkey atkey;
    atclient_atkey_init(&atkey);

    if ((ret = atclient_atkey_create_shared_key(&atkey, ATKEY_NAME, from_atsign, to_atsign, ATKEY_NAMESPACE)) != 0) {
      atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atclient_atkey_create_shared_key: %d\n", ret);
    }

    if((ret = atclient_notify_params_set_operation(&params, ATCLIENT_NOTIFY_OPERATION_UPDATE)) != 0) {
      atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atclient_notify_params_set_operation: %d\n", ret);
    }

    if((ret = atclient_notify_params_set_atkey(&params, &atkey)) != 0) {
      atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atclient_notify_params_set_atkey: %d\n", ret);
    }

    if((ret = atclient_notify_params_set_value(&params, line)) != 0) {
      atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atclient_notify_params_set_value: %d\n", ret);
    }

    if((ret = atclient_notify_params_set_should_encrypt(&params, true)) != 0) {
      atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atclient_notify_params_set_should_encrypt: %d\n", ret);
    }

    if((ret = atclient_notify_params_set_notification_expiry(&params, 5000)) != 0) {
      atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atclient_notify_params_set_notification_expiry: %d\n", ret);
    }

    pthread_mutex_lock(&client_mutex);
    if ((ret = atclient_notify(&atclient1, &params, NULL)) != 0) {
      atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atclient_notify: %d\n", ret);
    }
    pthread_mutex_unlock(&client_mutex);

    printf("%s%s%s: ", HBLU, from_atsign, reset);

    atclient_atkey_free(&atkey);
    atclient_notify_params_free(&params);
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
  atclient_monitor_set_read_timeout(monitor, READ_TIMEOUT); // blocking read takes 1 second to timeout
  if ((ret = atclient_monitor_start(monitor, MONITOR_REGEX, strlen(MONITOR_REGEX))) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "Failed to start monitor: %d\n", ret);
    goto exit;
  }
  pthread_mutex_unlock(&monitor_mutex);

  int tries = 1;

  while (true) {
    atclient_monitor_response message;
    atclient_monitor_response_init(&message);

    pthread_mutex_lock(&monitor_mutex);
    pthread_mutex_lock(&client_mutex);
    ret = atclient_monitor_read(monitor, ctx, &message, NULL);
    pthread_mutex_unlock(&monitor_mutex);
    pthread_mutex_unlock(&client_mutex);

    switch (message.type) {
    case ATCLIENT_MONITOR_MESSAGE_TYPE_NOTIFICATION: {
      if (strcmp(message.notification.id, "-1") == 0) {
        // We received a stats notification. Ignore it.
        break;
      }
      if (atclient_atnotification_is_decrypted_value_initialized(&(message.notification))) {
        const atclient_atnotification *notification = &(message.notification);
        printf("\n%s%s%s: %s\n", HGRN, notification->from, reset, notification->decrypted_value);
        printf("%s%s%s: ", HBLU, from_atsign, reset);
        fflush(stdout);
      }
      tries = 1;
    }
    case ATCLIENT_MONITOR_ERROR_READ: {
      if (message.error_read.error_code == MBEDTLS_ERR_SSL_TIMEOUT) {
        atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_DEBUG, "Read timed out.\n", ret);
        tries++;
      } else if (message.error_read.error_code < 0) {
        atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "Read failed with error code: %d\n",
                     message.error_read.error_code);
        tries++;
      } else if (message.error_read.error_code == 0) {
        // must reconnect IMMEDIATELY.
        atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "Read failed with error code 0. Reconnecting immediately.\n",
                     ret);
        tries = MAX_RETRIES;
      }
      if (tries >= MAX_RETRIES) {
        pthread_mutex_lock(&monitor_mutex);
        pthread_mutex_lock(&client_mutex);
        if (atclient_is_connected(ctx) && atclient_monitor_is_connected(monitor)) {
          atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_DEBUG, "Connection is still alive. Doing nothing.\n");
        } else {
          atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "Connection is dead. Reconnecting...\n");
          if ((ret = reconnect_clients(monitor, ctx, atserver_host, atserver_port, atkeys, from_atsign)) != 0) {
            atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "Failed to reconnect clients: %d\n", ret);
            pthread_mutex_unlock(&client_mutex);
            pthread_mutex_unlock(&monitor_mutex);
            break;
          }
          atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_INFO, "Successfully reconnected clients.\n");
        }
        pthread_mutex_unlock(&client_mutex);
        pthread_mutex_unlock(&monitor_mutex);
        tries = 1;
      }
      break;
    }
    case ATCLIENT_MONITOR_ERROR_PARSE_NOTIFICATION: {
      atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "ATCLIENT_MONITOR_ERROR_PARSE_NOTIFICATION error occurred: %d\n",
                   ret);
      break;
    }
    case ATCLIENT_MONITOR_ERROR_DECRYPT_NOTIFICATION: {
      atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR,
                   "ATCLIENT_MONITOR_ERROR_DECRYPT_NOTIFICATION error occurred: %d\n", ret);
      break;
    }
    default: {
      atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR,
                   "Received message type: %d, with atclient_monitor_read return value: %d\n", message.type, ret);
      break;
    }
    }

    atclient_monitor_response_free(&message);
    usleep(100);
  }
  goto exit;

exit: { return NULL; }
}

static int reconnect_clients(atclient *monitor, atclient *ctx, const char *atserver_host, const int atserver_port,
                             atclient_atkeys *atkeys, const char *from_atsign) {
  int ret = 1;

  /*
   * 1. Reconnect client connection
   */
  atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_DEBUG, "Reconnecting client connection...\n");
  if ((ret = atclient_pkam_authenticate(ctx, atserver_host, atserver_port, atkeys, from_atsign)) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atclient_pkam_authenticate: %d\n", ret);
    return ret;
  }
  atclient_set_read_timeout(ctx, READ_TIMEOUT); // blocking read takes X seconds to timeout
  atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_DEBUG, "Successfully established client connection.\n");

  /*
   * 2. Reconnect monitor connection
   */
  atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_DEBUG, "Reconnecting monitor connection...\n");
  if ((ret = atclient_monitor_pkam_authenticate(monitor, atserver_host, atserver_port, atkeys, from_atsign)) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atclient_pkam_authenticate: %d\n", ret);
    return ret;
  }
  atclient_monitor_set_read_timeout(monitor, READ_TIMEOUT); // blocking read takes X seconds to timeout
  atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_DEBUG, "Successfully established monitor connection.\n");

  /*
   * 3. Start monitor
   */
  atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_DEBUG, "Restarting monitor...\n");
  if ((ret = atclient_monitor_start(monitor, MONITOR_REGEX, strlen(MONITOR_REGEX))) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "Failed to start monitor: %d\n", ret);
    return ret;
  }
  atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_DEBUG, "Successfully restarted monitor.\n");

  /*
   * 4. Check if reconnection was *really* successful
   */
  if (ret == 0) {
    if (atclient_is_connected(ctx) && atclient_monitor_is_connected(monitor)) {
      atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_DEBUG, "Reconnection successful.\n", ret);
      ret = 0;
      return ret;
    } else {
      atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "Reconnection failed.\n", ret);
      ret = 1;
      return ret;
    }
  }
}
