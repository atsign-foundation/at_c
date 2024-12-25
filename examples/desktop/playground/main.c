#include <atlogger/atlogger.h>
#include <string.h>
#include <atclient/connection.h>

#define TAG "main"

int main() {
  int ret = 1;

  atlogger_set_logging_level(ATLOGGER_LOGGING_LEVEL_DEBUG);

  // Enter your code here

  const char *host = "vip.ve.atsign.zone";
  const int port = 64;

  unsigned char recv[1024];
  size_t recv_size = sizeof(recv);
  size_t recv_len = 0;

  atclient_connection connection;
  atclient_connection_init(&connection, ATCLIENT_CONNECTION_TYPE_ATSERVER);

  if((ret = atclient_connection_connect(&connection, host, port)) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atclient_connection_connect failed with exit code: %d\n", ret);
    goto exit;
  }

  atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_INFO, "Connected to %s:%d\n", host, port);

  atclient_connection_send(&connection, (unsigned char *)"bob🛠\n", strlen("bob🛠\n"), recv, recv_size, &recv_len);

  ret = 0;

exit: { return ret; }
}