#include <atclient/atclient.h>
#include <atclient/atclient_utils.h>
#include <atclient/atkey.h>
#include <atclient/atsign.h>
#include <atclient/constants.h>
#include <atclient/metadata.h>
#include <atclient/monitor.h>
#include <atlogger/atlogger.h>
#include <pthread.h>
#include <pwd.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define TAG "Debug"

#define ROOT_HOST "root.atsign.org"
#define ROOT_PORT 64

static int get_atsign_input(int argc, char *argv[], char **atsign_input);
static int set_up_atkeys(atclient_atkeys *atkeys, const char *atsign, const size_t atsignlen);

int main(int argc, char *argv[]) {
  int ret = 1;

  atlogger_set_logging_level(ATLOGGER_LOGGING_LEVEL_DEBUG);

  char *atsign = NULL;

  char *atserver_host = NULL;
  int atserver_port = -1;

  atclient_atkeys atkeys;
  atclient_atkeys_init(&atkeys);

  atclient atclient2;
  atclient_init(&atclient2);

  atclient monitor_conn;
  atclient_monitor_init(&monitor_conn);

  atclient_monitor_message *message = NULL;

  if ((ret = get_atsign_input(argc, argv, &atsign)) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "Failed to get atsign input (Example: \'./monitor -a @bob\')\n");
    goto exit;
  }

  if ((ret = set_up_atkeys(&atkeys, atsign, strlen(atsign))) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "Failed to set up atkeys: %d\n", ret);
    goto exit;
  }

  if ((ret = atclient_utils_find_atserver_address(ROOT_HOST, ROOT_PORT, atsign, &atserver_host, &atserver_port)) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "Failed to find atserver address\n");
    goto exit;
  }

  if ((ret = atclient_pkam_authenticate(&atclient2, atserver_host, atserver_port, &atkeys, atsign)) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "Failed to authenticate with PKAM\n");
    goto exit;
  }

  if ((ret = atclient_monitor_pkam_authenticate(&monitor_conn, atserver_host, atserver_port, &atkeys, atsign)) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "Failed to authenticate monitor with PKAM\n");
    goto exit;
  }

  if ((ret = atclient_monitor_start(&monitor_conn, ".*", strlen(".*"))) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "Monitor crashed\n");
    goto exit;
  }

  atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_DEBUG, "Starting main monitor loop...\n");
  while (true) {

    ret = atclient_monitor_read(&monitor_conn, &atclient2, &message, NULL);
    if (ret != 0) {
      atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "Failed to read monitor message: %d\n", ret);
      continue;
    }

    switch (message->type) {
    case ATCLIENT_MONITOR_MESSAGE_TYPE_NONE: {
      // atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_DEBUG, "Message type: ATCLIENT_MONITOR_MESSAGE_TYPE_NONE\n");
      break;
    }
    case ATCLIENT_MONITOR_MESSAGE_TYPE_NOTIFICATION: {
      // atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_DEBUG, "Message type: ATCLIENT_MONITOR_MESSAGE_TYPE_NOTIFICATION\n");
      // atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_DEBUG, "Message Body: %s\n", message->notification.value);
      if (strcmp(message->notification.id, "-1") == 0) {
        // ignore stats notification
        atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_DEBUG, "Received stats notification, ignoring it.\n");
        break;
      }
      if (atclient_atnotification_decryptedvalue_is_initialized(&message->notification)) {
        // atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_DEBUG, "Message id: %s\n", message->notification.id);
        atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_DEBUG, "decryptedvalue: \"%s\"\n",
                     message->notification.decryptedvalue);
      }
      break;
    }
    case ATCLIENT_MONITOR_MESSAGE_TYPE_DATA_RESPONSE: {
      // atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_DEBUG, "Message type: ATCLIENT_MONITOR_MESSAGE_TYPE_DATA_RESPONSE\n");
      // atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_DEBUG, "Message Body: %s\n", message->data_response);
      break;
    }
    case ATCLIENT_MONITOR_MESSAGE_TYPE_ERROR_RESPONSE: {
      // atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_DEBUG, "Message type:
      // ATCLIENT_MONITOR_MESSAGE_TYPE_ERROR_RESPONSE\n"); atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_DEBUG, "Message
      // Body: %s\n", message->error_response);
      break;
    }
    case ATCLIENT_MONITOR_EMPTY_READ:
    case ATCLIENT_MONITOR_ERROR_DECRYPT_NOTIFICATION:
    case ATCLIENT_MONITOR_ERROR_PARSE_NOTIFICATION: {
      atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_DEBUG, "Message type: %d\n", message->type);
      break;
    }
    }
    // sleep(3);
  }

  ret = 0;
  goto exit;
exit: {
  atclient_atkeys_free(&atkeys);
  free(atsign);
  atclient_monitor_free(&monitor_conn);
  atclient_monitor_message_free(message);
  return ret;
}
}

static int get_atsign_input(int argc, char *argv[], char **atsign_input) {
  int c;
  while ((c = getopt(argc, argv, "a:")) != -1) {
    switch (c) {
    case 'a':
      *atsign_input = optarg;
      break;
    }
  }

  if (*atsign_input == NULL) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "Please provide both atsigns with -a and -o flags\n");
    return 1;
  }

  return 0;
}

static int set_up_atkeys(atclient_atkeys *atkeys, const char *atsign, const size_t atsignlen) {
  int ret = 1;

  const size_t atkeyspathsize = 1024;
  char atkeyspath[atkeyspathsize];
  memset(atkeyspath, 0, atkeyspathsize);
  size_t atkeyspathlen;

  struct passwd *pw = getpwuid(getuid());
  const char *homedir = pw->pw_dir;
  snprintf(atkeyspath, atkeyspathsize, "%s/.atsign/keys/%s_key.atKeys", homedir, atsign);

  if ((ret = atclient_atkeys_populate_from_path(atkeys, atkeyspath)) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "Failed to populate atkeys from path: %d\n", ret);
    goto exit;
  }

  goto exit;

exit: { return ret; }
}
