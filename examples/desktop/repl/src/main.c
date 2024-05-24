#include <atclient/atbytes.h>
#include <atclient/atclient.h>
#include <atclient/atkeys.h>
#include <atclient/atkeysfile.h>
#include <atclient/connection.h>
#include <atlogger/atlogger.h>
#include <pwd.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define TAG "REPL"

static char *get_home_dir() {
  struct passwd *pw = getpwuid(getuid());
  return pw->pw_dir;
}

int main(int argc, char *argv[]) {
  int ret = 1;

  atlogger_set_logging_level(ATLOGGER_LOGGING_LEVEL_DEBUG);

  const short atkeysfilepathsize = 256;
  char atkeysfilepath[atkeysfilepathsize];
  memset(atkeysfilepath, 0, sizeof(char) * atkeysfilepathsize); // Clear the buffer (for safety)

  const size_t buffersize = 2048;
  char buffer[buffersize];
  memset(buffer, 0, sizeof(char) * buffersize); // Clear the buffer (for safety
  size_t bufferlen = 0;

  const size_t recvsize = 8192 * 4;
  unsigned char recv[recvsize];
  memset(recv, 0, sizeof(unsigned char) * recvsize); // Clear the buffer (for safety
  size_t recvlen = 0;

  char *atserver_host = NULL;
  int atserver_port = -1;

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
  char *homedir = get_home_dir();
  if (homedir == NULL || strlen(homedir) == 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "Failed to get home directory\n");
    ret = 1;
    goto exit;
  }

  sprintf(atkeysfilepath, "%s/.atsign/keys/%s_key.atKeys", homedir, atsign);
  if ((ret = atclient_atkeys_populate_from_path(&atkeys, atkeysfilepath)) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "Failed to read atKeys file at path \"%s\"\n", atkeysfilepath);
    goto exit;
  }
  atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_INFO, "Successfully read atKeys file at path %s\n", atkeysfilepath);

  if ((ret = atclient_find_atserver_address(roothost, rootport, atsign, &atserver_host, &atserver_port)) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR,
                 "atclient_find_atserver_address: %d | failed to find atserver address\n", ret);
    goto exit;
  }

  ret = atclient_pkam_authenticate(&atclient, atserver_host, atserver_port, &atkeys, atsign);
  if (ret != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atclient_pkam_authenticate: %d | failed to authenticate\n", ret);
    goto exit;
  }
  atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_INFO, "Successfully PKAM Authenticated with atSign \"%s\"\n", atsign);

  bool loop = true;
  do {
    printf("Enter command: \n");
    fgets(buffer, buffersize, stdin);
    bufferlen = strlen(buffer);
    if (strncmp(buffer, "/exit", strlen("/exit")) == 0) {
      atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_INFO, "Exiting REPL...\n");
      loop = false;
      continue;
    }
    ret = atclient_connection_send(&atclient.atserver_connection, (const unsigned char *)buffer, bufferlen, recv,
                                   recvsize, &recvlen);
    if (ret != 0) {
      atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atclient_connection_send: %d | failed to send command\n", ret);
      goto exit;
    }
    memset(buffer, 0, sizeof(char) * buffersize);
    memset(recv, 0, sizeof(unsigned char) * recvsize);
  } while (loop);

  ret = 0;
  goto exit;

exit: {
  free(atserver_host);
  free(temp);
  atclient_free(&atclient);
  atclient_atkeys_free(&atkeys);
  return ret;
}
}