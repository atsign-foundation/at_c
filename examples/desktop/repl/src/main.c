#include <atclient/atbytes.h>
#include <atclient/atclient.h>
#include <atclient/atkeys.h>
#include <atclient/atkeysfile.h>
#include <atclient/connection.h>
#include <atlogger/atlogger.h>
#include <pwd.h>
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
  atclient_atlogger_set_logging_level(ATLOGGER_LOGGING_LEVEL_DEBUG);

  const unsigned long cmdlen = 32768;
  atclient_atbytes cmd;
  atclient_atbytes_init(&cmd, cmdlen);

  const unsigned long recvlen = 32768;
  atclient_atbytes recv;
  atclient_atbytes_init(&recv, recvlen);

  if (argc < 2 || argc > 3) {
    atclient_atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "Usage: ./repl <atsign> [rootUrl]");
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
    char *temp = malloc(strlen(atsign) + 2);
    strcpy(temp, "@");
    strcat(temp, atsign);
    atsign = temp;
  }
  atclient_atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_INFO, "Using atSign \"%s\" and rootUrl \"%s:%d\"\n", atsign,
                        roothost, rootport);

  atclient_atkeys atkeys;
  atclient_atkeys_init(&atkeys);
  char *homedir = get_home_dir();
  if (homedir == NULL || strlen(homedir) == 0) {
    atclient_atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "Failed to get home directory\n");
    ret = 1;
    goto exit;
  }
  char atkeysfilepath[1024];
  sprintf(atkeysfilepath, "%s/.atsign/keys/%s_key.atKeys", homedir, atsign);
  if (atclient_atkeys_populate_from_path(&atkeys, atkeysfilepath) != 0) {
    atclient_atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "Failed to read atKeys file at path %s\n", atkeysfilepath);
    ret = 1;
    goto exit;
  }
  atclient_atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_INFO, "Read atKeys file at path %s\n", atkeysfilepath);

  atclient atclient;
  atclient_init(&atclient);
  ret = atclient_start_root_connection(&atclient, roothost, rootport);
  if (ret != 0) {
    atclient_atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR,
                          "atclient_start_root_connection: %d | failed to connect to root\n", ret);
    goto exit;
  }

  ret = atclient_pkam_authenticate(&atclient, atkeys, atsign, strlen(atsign));
  if (ret != 0) {
    atclient_atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR,
                          "atclient_pkam_authenticate: %d | failed to authenticate\n", ret);
    goto exit;
  }
  atclient_atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_INFO, "Successfully PKAM Authenticated with atSign \"%s\"\n",
                        atsign);

  const unsigned long bufferlen = 1024;
  char buffer[bufferlen];

  int loop = 1;
  do {
    memset(buffer, 0, sizeof(char) * bufferlen);
    printf("Enter command: \n");
    fgets(buffer, bufferlen, stdin);
    ret = atclient_atbytes_convert(&cmd, buffer, strlen(buffer));
    if (ret != 0) {
      atclient_atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR,
                            "atclient_atbytes_convert: %d | failed to convert command\n", ret);
      goto exit;
    }
    if (strncmp(cmd.bytes, "/exit", strlen("/exit")) == 0) {
      atclient_atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_INFO, "Exiting REPL...\n");
      loop = 0;
      continue;
    }
    ret =
        atclient_connection_send(&atclient.secondary_connection, cmd.bytes, cmd.olen, recv.bytes, recv.len, &recv.olen);
    if (ret != 0) {
      atclient_atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR,
                            "atclient_connection_send: %d | failed to send command\n", ret);
      goto exit;
    }
    atclient_atbytes_reset(&cmd);
    atclient_atbytes_reset(&recv);

  } while (loop == 1);

  ret = 0;
  goto exit;

exit: {
  atclient_atstr_free(&cmd);
  atclient_atstr_free(&recv);
  return ret;
}
}