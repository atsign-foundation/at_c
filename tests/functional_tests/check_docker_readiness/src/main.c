#include <atclient/atclient.h>
#include <atclient/atkeys.h>
#include <atclient/connection.h>
#include <atlogger/atlogger.h>
#include <pwd.h>
#include <string.h>
#include <unistd.h>

#define TAG "check_docker_readiness"

#define ATSIGN_WITHOUT_AT "alice🛠"
#define ATSIGN_WITH_AT "@alice🛠"

#define VE_ATDIRECTORY_HOST "vip.ve.atsign.zone"
#define VE_ATDIRECTORY_PORT 64

static int get_atkeys_path(const char *atsign, char **path);

int main() {
  int ret = 1;

  atlogger_set_logging_level(ATLOGGER_LOGGING_LEVEL_DEBUG);

  atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_INFO, "Checking if virtual environment is ready...\n");

  atclient_connection atdirectory;
  atclient_connection_init(&atdirectory, ATCLIENT_CONNECTION_TYPE_ATDIRECTORY);

  atclient_connection atserver;
  atclient_connection_init(&atserver, ATCLIENT_CONNECTION_TYPE_ATSERVER);

  atclient_atkeys atkeys;
  atclient_atkeys_init(&atkeys);

  atclient atclient;
  atclient_init(&atclient);

  atclient_authenticate_options authenticate_options;
  atclient_authenticate_options_init(&authenticate_options);

  char *path = NULL;

  const size_t recv_size = 1024;
  unsigned char recv[recv_size];
  memset(recv, 0, recv_size);
  size_t recv_len = 0;

  const size_t host_size = 256;
  char host[host_size];
  memset(host, 0, sizeof(char) * host_size);

  const size_t port_str_size = 8;
  char port_str[port_str_size];
  memset(port_str, 0, sizeof(char) * port_str_size);

  uint16_t port = 0;

  // Check if we can connect to root
  if ((ret = atclient_connection_connect(&atdirectory, VE_ATDIRECTORY_HOST, VE_ATDIRECTORY_PORT)) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "Failed to connect to root atdirectory\n");
    goto exit;
  }
  atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_INFO, "Connected to atDirectory %s:%d\n", VE_ATDIRECTORY_HOST,
               VE_ATDIRECTORY_PORT);

  // Check if we can send alice
  const char *command = ATSIGN_WITHOUT_AT "\r\n";
  atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_INFO, "Sending \"%s\" to atDirectory...\n", ATSIGN_WITHOUT_AT);
  if ((ret = atclient_connection_send(&atdirectory, command, strlen(ATSIGN_WITHOUT_AT) + 2, recv, recv_size,
                                      &recv_len) != 0)) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "Failed to send alice to root atdirectory\n");
    goto exit;
  }
  atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_INFO, "Sent \"%s\" to atDirectory\n", ATSIGN_WITHOUT_AT);
  atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_INFO, "Received \"%s\" from atDirectory\n", recv);

  // Ensure that response was not "null" string
  if (strcmp((char *)recv, "null") == 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "Received \"null\" from atDirectory\n");
    ret = 1;
    goto exit;
  }

  // Populate host and port_str, recv is something like "vip.ve.atsign.zone:25000"
  char *port_str_ptr = strchr((char *)recv, ':');
  if (port_str_ptr == NULL) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "Failed to parse port from response\n");
    ret = 1;
    goto exit;
  }
  port = (uint16_t)atoi(port_str_ptr + 1);

  snprintf(host, port_str_ptr - (char *)recv + 1, "%s", (char *)recv);
  snprintf(port_str, strlen(port_str_ptr), "%s", port_str_ptr + 1);

  atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_INFO, "Extracted host: \"%s\"\n", host);
  atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_INFO, "Extracted port: \"%d\"\n", port);

  // Check if we can connect to alice
  if ((ret = atclient_connection_connect(&atserver, host, port)) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "Failed to connect to alice's atServer\n");
    goto exit;
  }

  // Check if we can talk to alice's atServer
  const char *command2 = "noop:0\r\n";
  atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_INFO, "Sending \"%s\" to alice's atServer...\n", command2);
  if ((ret = atclient_connection_send(&atserver, command2, strlen(command2), recv, recv_size, &recv_len) != 0)) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "Failed to send command to alice's atServer\n");
    goto exit;
  }
  atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_INFO, "Sent \"%s\" to alice's atServer\n", command2);
  atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_INFO, "Received \"%s\" from alice's atServer\n", recv);

  // Check if we can pkam authenticate to alice's atServer
  if ((ret = get_atkeys_path(ATSIGN_WITH_AT, &path)) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "Failed to get atkeys path for atSign \"%s\"\n", ATSIGN_WITH_AT);
    goto exit;
  }

  // Prepare to PKAM auth:

  // > Populate atKeys
  if ((ret = atclient_atkeys_populate_from_path(&atkeys, path)) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "Failed to populate atkeys from path \"%s\"\n", path);
    goto exit;
  }

  // > Set atDirectory host and port
  if ((ret = atclient_authenticate_options_set_atdirectory_host(&authenticate_options, VE_ATDIRECTORY_HOST)) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "Failed to set atdirectory host in authenticate options\n");
    goto exit;
  }

  if ((ret = atclient_authenticate_options_set_atdirectory_port(&authenticate_options, VE_ATDIRECTORY_PORT)) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "Failed to set atdirectory port in authenticate options\n");
    goto exit;
  }

  // PKAM Auth
  if ((ret = atclient_pkam_authenticate(&atclient, ATSIGN_WITH_AT, &atkeys, &authenticate_options, NULL)) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "Failed to pkam authenticate to alice's atServer\n");
    goto exit;
  }
  atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_INFO, "Successfully PKAM authenticated to alice's atServer\n");

  atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_INFO, "Virtual environment is deemed ready\n");

  ret = 0;

exit: {
  atclient_connection_free(&atdirectory);
  atclient_connection_free(&atserver);
  atclient_atkeys_free(&atkeys);
  atclient_free(&atclient);
  atclient_authenticate_options_free(&authenticate_options);
  free(path);
  return ret;
}
}

static int get_atkeys_path(const char *atsign, char **path) {
  struct passwd *pw = getpwuid(getuid());
  const char *homedir = pw->pw_dir;
  const size_t path_size = strlen(homedir) + strlen("/.atsign/keys/") + strlen(atsign) + strlen("_key.atkeys") + 1;
  *path = (char *)malloc(sizeof(char) * path_size);
  if (*path == NULL) {
    return 1;
  }
  memset(*path, 0, sizeof(char) * path_size);
  snprintf(*path, path_size, "%s/.atsign/keys/%s_key.atKeys", homedir, atsign);
  return 0;
}
