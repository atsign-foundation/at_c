#include <atclient/atclient.h>
#include <atclient/atclient_utils.h>
#include <atclient/atkeys.h>
#include <atclient/atkeys_file.h>
#include <atclient/connection.h>
#include <atlogger/atlogger.h>
#include <pwd.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define TAG "repl"

int main(int argc, char *argv[]) {
  int ret = 1;

  atlogger_set_logging_level(ATLOGGER_LOGGING_LEVEL_DEBUG);

  const size_t buffersize = 2048;
  char buffer[buffersize];
  memset(buffer, 0, sizeof(char) * buffersize);
  size_t bufferlen = 0;

  const size_t recvsize = 8192 * 4;
  unsigned char recv[recvsize];
  memset(recv, 0, sizeof(unsigned char) * recvsize);
  size_t recvlen = 0;

  atclient atclient;
  atclient_init(&atclient);

  char *temp = NULL;

  if (argc < 2 || argc > 3) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "Usage: ./repl <atsign> [rootUrl]");
    ret = 1;
    goto exit;
  }

  const char *atsign = argv[1];
  const char *rooturl = argc == 3 ? argv[2] : "root.atsign.org:64";
  char *rooturlcopy = strdup(rooturl); // Create a copy of rootUrl because strtok modifies the original string
  char *roothost = strtok(rooturlcopy, ":");
  char *portstr = strtok(NULL, ":");
  int rootport =
      portstr ? atoi(portstr) : 64; // Convert the port part to an integer. If portStr is NULL, port will be 0.

  // if atSign doesn't start with `@`, then add it
  if (atsign[0] != '@') {
    const short tempsize = strlen(atsign) + 2;
    temp = (char *)malloc(sizeof(char) * tempsize);
    memset(temp, 0, sizeof(char) * tempsize); // Clear the buffer (for safety
    snprintf(temp, tempsize, "@%s", atsign);  // Add 1 for the `@` and 1 for the null terminator
    atsign = temp;
  }
  atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_INFO, "Using atSign \"%s\" and rootUrl \"%s:%d\"\n", atsign, roothost,
               rootport);

  atclient_atkeys atkeys;
  atclient_atkeys_init(&atkeys);

  if ((ret = atclient_pkam_authenticate(&atclient, atsign, &atkeys, NULL)) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atclient_pkam_authenticate: %d | failed to authenticate\n", ret);
    goto exit;
  }
  atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_INFO, "Successfully PKAM Authenticated with atSign \"%s\"\n", atsign);

  bool loop = true;
  do {
    printf("Enter command: ");
    fgets(buffer, buffersize, stdin);
    bufferlen = strlen(buffer);

    if (bufferlen <= 0) {
      continue;
    }

    if (buffer[0] != '/') {
      ret = atclient_connection_send(&(atclient.atserver_connection), (const unsigned char *)buffer, bufferlen, recv,
                                     recvsize, &recvlen);
      if (ret != 0) {
        atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atclient_connection_send: %d | failed to send command: %s\n",
                     ret, buffer);
      }
    } else {

      char *command = strtok(buffer, " ");
      if (command == NULL) {
        atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "No command entered\n");
        continue;
      }
      command[strcspn(command, "\n")] = 0;

      if (strcmp(command, "/exit") == 0) {
        loop = false;
        continue;
      } else if (strcmp(command, "/get") == 0) {
        char *atkeystr = strtok(NULL, " ");
        if (atkeystr == NULL) {
          atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "No atKey entered\n");
          continue;
        }
        atkeystr[strcspn(atkeystr, "\n")] = 0;
        char *value = NULL;
        atclient_atkey atkey;
        atclient_atkey_init(&atkey);

        if ((ret = atclient_atkey_from_string(&atkey, atkeystr))) {
          atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atclient_atkey_from_string: %d | failed to parse atKey\n",
                       ret);
          goto get_end;
        }

        const atclient_atkey_type atkey_type = atclient_atkey_get_type(&atkey);

        switch (atkey_type) {
        case ATCLIENT_ATKEY_TYPE_UNKNOWN: {
          atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "Unknown atKey type\n");
          goto get_end;
        }
        case ATCLIENT_ATKEY_TYPE_PUBLIC_KEY: {
          if ((ret = atclient_get_public_key(&atclient, &atkey, &value, NULL)) != 0) {
            atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atclient_get_public_key: %d | failed to get public key\n",
                         ret);
            goto get_end;
          }
          atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_INFO, "Value: \"%s\"\n", value);
          break;
        }
        case ATCLIENT_ATKEY_TYPE_SELF_KEY: {
          if ((ret = atclient_get_self_key(&atclient, &atkey, &value, NULL)) != 0) {
            atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atclient_get_self_key: %d | failed to get self key\n",
                         ret);
            goto get_end;
          }
          atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_INFO, "Value: \"%s\"\n", value);
          break;
        }
        case ATCLIENT_ATKEY_TYPE_SHARED_KEY: {
          if ((ret = atclient_get_shared_key(&atclient, &atkey, &value, NULL)) != 0) {
            atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atclient_get_shared_key: %d | failed to get shared key\n",
                         ret);
            goto get_end;
          }
          atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_INFO, "Value: \"%s\"\n", value);
          break;
        }
        }

      get_end: {
        free(value);
        atclient_atkey_free(&atkey);
      }
      } else if (strcmp(command, "/put") == 0) {
        // /put <atkey> <value>
        char *atkeystr = strtok(NULL, " ");
        if (atkeystr == NULL) {
          atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "No atKey entered\n");
          continue;
        }
        atkeystr[strcspn(atkeystr, "\n")] = 0;
        char *value = strtok(NULL, "\n");
        if (value == NULL) {
          atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "No value entered\n");
          continue;
        }
        atclient_atkey atkey;
        atclient_atkey_init(&atkey);
        if ((ret = atclient_atkey_from_string(&atkey, atkeystr)) != 0) {
          atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atclient_atkey_from_string: %d | failed to parse atKey\n",
                       ret);
          goto put_end;
        }
        const atclient_atkey_type atkey_type = atclient_atkey_get_type(&atkey);
        if (atkey_type == ATCLIENT_ATKEY_TYPE_UNKNOWN) {
          atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "Unknown atKey type\n");
          goto put_end;
        } else if (atkey_type == ATCLIENT_ATKEY_TYPE_PUBLIC_KEY) {
          if ((ret = atclient_put_public_key(&atclient, &atkey, value, NULL, NULL)) != 0) {
            atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atclient_put_public_key: %d | failed to put public key\n",
                         ret);
            goto put_end;
          }
        } else if (atkey_type == ATCLIENT_ATKEY_TYPE_SELF_KEY) {
          if ((ret = atclient_put_self_key(&atclient, &atkey, value, NULL, NULL)) != 0) {
            atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atclient_put_self_key: %d | failed to put self key\n",
                         ret);
            goto put_end;
          }
        } else if (atkey_type == ATCLIENT_ATKEY_TYPE_SHARED_KEY) {
          if ((ret = atclient_put_shared_key(&atclient, &atkey, value, NULL, NULL)) != 0) {
            atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atclient_put_shared_key: %d | failed to put shared key\n",
                         ret);
            goto put_end;
          }
        }
      put_end: { atclient_atkey_free(&atkey); }
      } else if (strcmp(command, "/scan") == 0) {
        atclient_get_atkeys_request_options request_options;
        atclient_get_atkeys_request_options_init(&request_options);
        char *regex = NULL;
        char *saveptr = NULL;
        regex = strtok_r(NULL, " ", &saveptr);
        if (regex != NULL) {
          regex[strcspn(regex, "\n")] = 0;

          if ((ret = atclient_get_atkeys_request_options_set_regex(&request_options, regex)) != 0) {
            atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR,
                         "atclient_get_atkeys_request_options_set_regex: %d | failed to set regex\n", ret);
            goto scan_end;
          }
        }
        atclient_atkey *arr = NULL;
        size_t arrlen = 0;
        if ((ret = atclient_get_atkeys(&atclient, &arr, &arrlen, &request_options)) != 0) {
          atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atclient_get_atkeys: %d | failed to get atKeys\n", ret);
          goto scan_end;
        }
        char *atkeystr = NULL;
        for (size_t i = 0; i < arrlen; i++) {
          atclient_atkey_to_string(&arr[i], &atkeystr);
          atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_INFO, "atKey[%i]: \'%s\'\n", i, atkeystr);
          free(atkeystr);
          atkeystr = NULL;
        }
      scan_end: {
        for (size_t i = 0; i < arrlen; i++) {
          atclient_atkey_free(&arr[i]);
        }
        free(arr);
        atclient_get_atkeys_request_options_free(&request_options);
      }
      } else if (strcmp(command, "/delete") == 0) {
        // /delete <atkey>
        char *atkeystr = strtok(NULL, " ");
        if (atkeystr == NULL) {
          atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "No atKey entered\n");
          continue;
        }
        atkeystr[strcspn(atkeystr, "\n")] = 0; // Remove the newline character
        atclient_atkey atkey;
        atclient_atkey_init(&atkey);
        if ((ret = atclient_atkey_from_string(&atkey, atkeystr)) != 0) {
          atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atclient_atkey_from_string: %d | failed to parse atKey\n",
                       ret);
          goto delete_end;
        }
        if ((ret = atclient_delete(&atclient, &atkey, NULL, NULL)) != 0) {
          atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atclient_delete: %d | failed to delete atKey\n", ret);
          goto delete_end;
        }
        atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_INFO, "Deleted atKey: %s\n", atkeystr);
      delete_end: { atclient_atkey_free(&atkey); }
      } else if (strcmp(command, "/deleteall") == 0) {
        atclient_atkey *arr = NULL;
        size_t arrlen = 0;
        if ((ret = atclient_get_atkeys(&atclient, &arr, &arrlen, NULL)) != 0) {
          atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atclient_get_atkeys: %d | failed to get atKeys\n", ret);
          goto deleteall_end;
        }
        char *atkeystr = NULL;
        for (size_t i = 0; i < arrlen; i++) {
          if ((ret = atclient_delete(&atclient, &arr[i], NULL, NULL)) != 0) {
            atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atclient_delete: %d | failed to delete atKey\n", ret);
            continue;
          }
          atclient_atkey_to_string(&arr[i], &atkeystr);
          atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_INFO, "Deleted atKey: %s\n", atkeystr);
          free(atkeystr);
          atkeystr = NULL;
        }
      deleteall_end: {
        for (size_t i = 0; i < arrlen; i++) {
          atclient_atkey_free(&arr[i]);
        }
        free(arr);
      }
      } else {
        atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "Unknown command: %s\n", command);
      }
    }

    memset(buffer, 0, sizeof(char) * buffersize);
    memset(recv, 0, sizeof(unsigned char) * recvsize);

  } while (loop);

  ret = 0;
  goto exit;

exit: {
  free(temp);
  atclient_free(&atclient);
  atclient_atkeys_free(&atkeys);
  atclient_pkam_authenticate_options_free(&options);
  return ret;
}
}