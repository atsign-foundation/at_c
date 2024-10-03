#include <atclient/connection.h>
#include <atlogger/atlogger.h>
#include <mbedtls/ssl.h>

#define TAG "main"

int main() {
  int ret = 1;

  atlogger_set_logging_level(ATLOGGER_LOGGING_LEVEL_DEBUG);

  atclient_connection connection;
  atclient_connection_init(&connection, ATCLIENT_CONNECTION_TYPE_ATSERVER);

  if ((ret = atclient_connection_connect(&connection, "root.atsign.org", 64)) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "Failed to connect...\n");
    return ret;
  }

  mbedtls_ssl_context ssl = connection.ssl;

  mbedtls_ssl_close_notify(&ssl);

  const size_t buf_size = 8192;
  unsigned char buf[buf_size];
  memset(buf, 0, sizeof(unsigned char) * buf_size);

  while (1) {
    ret = mbedtls_ssl_read(&ssl, buf, buf_size);
    //   log ret
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_INFO, "mbedtls_ssl_read returned: %d\n", ret);
    memset(buf, 0, sizeof(unsigned char) * buf_size);
  }
  return ret;
}