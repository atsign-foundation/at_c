#include <atclient/connection.h>
#include <atlogger/atlogger.h>
#include <functional_tests/helpers.h>
#include <string.h>

#define TAG "test_atclient_connection"

#define ROOT_HOST "root.atsign.org"
#define ROOT_PORT 64

static int assert_equals(bool actual, bool expected);

static int test_1_initialize(atclient_connection *conn);
static int test_2_connect(atclient_connection *conn);
static int test_3_is_connected_should_be_true(atclient_connection *conn);
static int test_4_send(atclient_connection *conn);
static int test_5_disconnect(atclient_connection *conn);
static int test_6_is_connected_should_be_false(atclient_connection *conn);
static int test_7_send_should_fail(atclient_connection *conn); // should fail, a failuer to send will return 0
static int test_8_reconnect(atclient_connection *conn);
static int test_9_is_connected_should_be_true(atclient_connection *conn);
static int test_10_free(atclient_connection *conn);

// simulating a server that is not responding back
static int test_11_initialize(atclient_connection *conn);
static int test_12_connect(atclient_connection *conn);
static int test_13_is_connected_should_be_true(atclient_connection *conn);
static int test_14_simulate_server_not_responding(atclient_connection *conn);
static int test_15_send_should_fail(atclient_connection *conn);
static int test_16_is_connected_should_be_false(atclient_connection *conn);
static int test_17_should_be_connected_should_be_true(atclient_connection *conn);

int main(int argc, char *argv[]) {
  int ret = 1;

  atlogger_set_logging_level(ATLOGGER_LOGGING_LEVEL_DEBUG);

  atclient_connection root_conn;

  if ((ret = test_1_initialize(&root_conn)) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "test_1_initialize: %d\n", ret);
    goto exit;
  }

  if ((ret = test_2_connect(&root_conn)) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "test_2_connect: %d\n", ret);
    goto exit;
  }

  if ((ret = test_3_is_connected_should_be_true(&root_conn)) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "test_3_is_connected: %d\n", ret);
    goto exit;
  }

  if ((ret = test_4_send(&root_conn)) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "test_4_send: %d\n", ret);
    goto exit;
  }

  if ((ret = test_5_disconnect(&root_conn)) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "test_5_disconnect: %d\n", ret);
    goto exit;
  }

  if ((ret = test_6_is_connected_should_be_false(&root_conn)) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "test_6_is_connected_should_be_false: %d\n", ret);
    goto exit;
  }

  if ((ret = test_7_send_should_fail(&root_conn)) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "test_7_send_should_fail: %d\n", ret);
    goto exit;
  }

  if ((ret = test_8_reconnect(&root_conn)) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "test_7_reconnect: %d\n", ret);
    goto exit;
  }

  if ((ret = test_9_is_connected_should_be_true(&root_conn)) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "test_8_is_connected: %d\n", ret);
    goto exit;
  }

  if ((ret = test_10_free(&root_conn)) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "test_9_free: %d\n", ret);
    goto exit;
  }

  if ((ret = test_11_initialize(&root_conn)) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "test_11_initialize: %d\n", ret);
    goto exit;
  }

  if ((ret = test_12_connect(&root_conn)) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "test_12_connect: %d\n", ret);
    goto exit;
  }

  if ((ret = test_13_is_connected_should_be_true(&root_conn)) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "test_13_is_connected: %d\n", ret);
    goto exit;
  }

  if ((ret = test_14_simulate_server_not_responding(&root_conn)) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "test_14_simulate_server_not_responding: %d\n", ret);
    goto exit;
  }

  if ((ret = test_15_send_should_fail(&root_conn)) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "test_15_send_should_fail: %d\n", ret);
    goto exit;
  }

  if ((ret = test_16_is_connected_should_be_false(&root_conn)) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "test_16_is_connected_should_be_false: %d\n", ret);
    goto exit;
  }

  if ((ret = test_17_should_be_connected_should_be_true(&root_conn)) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "test_17_should_be_connected_should_be_true: %d\n", ret);
    goto exit;
  }

  ret = 0;
  goto exit;
exit: { return ret; }
}

static int assert_equals(bool actual, bool expected) {
  if (actual != expected) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "Expected %d, but got %d\n", expected, actual);
    return 1;
  }
  return 0;
}

static int test_1_initialize(atclient_connection *conn) {
  atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_INFO, "test_1_initialize Begin\n");

  int ret = 1;

  atclient_connection_init(conn, ATCLIENT_CONNECTION_TYPE_DIRECTORY);

  if ((ret = assert_equals(conn->should_be_connected, false)) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "conn->should_be_connected should be false, but is true\n");
    goto exit;
  }

  ret = 0;
  goto exit;
exit: {
  atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_INFO, "test_1_initialize End: %d\n", ret);
  return ret;
}
}

static int test_2_connect(atclient_connection *conn) {
  atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_INFO, "test_2_connect Begin\n");

  int ret = 1;

  ret = atclient_connection_connect(conn, ROOT_HOST, ROOT_PORT);
  if (ret != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "Failed to connect: %d\n", ret);
    goto exit;
  }

  if ((ret = assert_equals(conn->should_be_connected, true)) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "root_conn.should_be_connected should be true, but is false\n");
    goto exit;
  }

  ret = 0;
  goto exit;
exit: {
  atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_INFO, "test_2_connect End: %d\n", ret);
  return ret;
}
}

static int test_3_is_connected_should_be_true(atclient_connection *conn) {
  atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_INFO, "test_3_is_connected Begin\n");

  int ret = 1;

  ret = atclient_connection_is_connected(conn);
  if (ret != 1) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "Failed to connect: %d\n", ret);
    goto exit;
  }

  ret = 0;
  goto exit;
exit: {
  atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_INFO, "test_3_is_connected End: %d\n", ret);
  return ret;
}
}

static int test_4_send(atclient_connection *conn) {
  atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_INFO, "test_4_send Begin\n");

  int ret = 1;

  const unsigned char *send_data = (const unsigned char *)"12alpaca\r\n";
  const size_t send_data_len = strlen((const char *)send_data);

  const size_t recvsize = 1024;
  unsigned char recv[1024];
  size_t recvlen = 0;

  ret = atclient_connection_send(conn, send_data, send_data_len, recv, recvsize, &recvlen);
  if (ret != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "Failed to send: %d\n", ret);
    goto exit;
  }

  atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_INFO, "Received: %s\n", recv);

  ret = 0;
  goto exit;
exit: { return ret; }
}

static int test_5_disconnect(atclient_connection *conn) {
  atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_INFO, "test_5_disconnect Begin\n");

  int ret = 1;

  ret = atclient_connection_disconnect(conn);
  if (ret != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "Failed to disconnect: %d\n", ret);
    goto exit;
  }

  if ((ret = assert_equals(conn->should_be_connected, false)) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "root_conn.should_be_connected should be false, but is true\n");
    goto exit;
  }

  ret = 0;
  goto exit;
exit: {
  atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_INFO, "test_5_disconnect End: %d\n", ret);
  return ret;
}
}

static int test_6_is_connected_should_be_false(atclient_connection *conn) {
  atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_INFO, "test_6_is_connected_should_be_false Begin\n");

  int ret;

  ret = atclient_connection_is_connected(conn);
  if (ret == 1) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR,
                 "atclient_connection_is_connected returned true when it should have been false: %d\n", ret);
    goto exit;
  }

  ret = 0;
  goto exit;
exit: {
  atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_INFO, "test_6_is_connected_should_be_false End: %d\n", ret);
  return ret;
}
}

static int test_7_send_should_fail(atclient_connection *conn) {
  atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_INFO, "test_7_send_should_fail\n");

  int ret = 1;

  const unsigned char *send_data = (const unsigned char *)"12alpaca\r\n";
  const size_t send_data_len = strlen((const char *)send_data);

  const size_t recvsize = 1024;
  unsigned char recv[recvsize];
  size_t recvlen = 0;

  ret = atclient_connection_send(conn, send_data, send_data_len, recv, recvsize, &recvlen);
  if (ret == 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR,
                 "Successfully sent \"%s\" when it should have resulted in a failure: %d\n", ret);
    ret = 1;
    goto exit;
  }

  atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_INFO,
               "Successfully failed at sending message to a disconnected connection\n");

  ret = 0;
  goto exit;
exit: {
  atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_INFO, "test_7_send_should_fail End: %d\n", ret);
  return ret;
}
}

static int test_8_reconnect(atclient_connection *conn) {
  atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_INFO, "test_8_reconnect Begin\n");

  int ret = 1;

  ret = atclient_connection_connect(conn, ROOT_HOST, ROOT_PORT);
  if (ret != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "Failed to reconnect: %d\n", ret);
    goto exit;
  }

  if (!conn->should_be_connected) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "ctx->should_be_connected should be true, but is false\n");
    ret = 1;
    goto exit;
  }

  ret = 0;
  goto exit;
exit: {
  atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_INFO, "test_8_reconnect End: %d\n", ret);
  return ret;
}
}

static int test_9_is_connected_should_be_true(atclient_connection *conn) {
  atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_INFO, "test_9_is_connected_should_be_true Begin\n");

  int ret = 1;

  ret = atclient_connection_is_connected(conn);
  if (ret != 1) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "Failed to connect: %d\n", ret);
    goto exit;
  }

  ret = 0;
  goto exit;
exit: { return ret; }
}

static int test_10_free(atclient_connection *conn) {
  int ret = 1;

  atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_INFO, "test_10_free Begin\n");

  atclient_connection_free(conn);

  if ((ret = assert_equals(conn->should_be_connected, false)) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "conn->should_be_connected should be false, but is true\n");
    goto exit;
  }

exit: {
  atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_INFO, "test_10_free End\n");
  return ret;
}
}

static int test_11_initialize(atclient_connection *conn) {
  atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_INFO, "test_11_initialize Begin\n");

  int ret = 1;

  atclient_connection_init(conn, ATCLIENT_CONNECTION_TYPE_DIRECTORY);

  if ((ret = assert_equals(conn->should_be_connected, false)) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "conn->should_be_connected should be false, but is true\n");
    goto exit;
  }

  ret = 0;
  goto exit;
exit: {
  atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_INFO, "test_11_initialize End: %d\n", ret);
  return ret;
}
}

static int test_12_connect(atclient_connection *conn) {
  atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_INFO, "test_12_connect Begin\n");

  int ret = 1;

  ret = atclient_connection_connect(conn, ROOT_HOST, ROOT_PORT);
  if (ret != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "Failed to connect: %d\n", ret);
    goto exit;
  }

  ret = 0;
  goto exit;
exit: {
  atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_INFO, "test_12_connect End: %d\n", ret);
  return ret;
}
}

static int test_13_is_connected_should_be_true(atclient_connection *conn) {
  atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_INFO, "test_13_is_connected Begin\n");

  int ret = 1;

  ret = atclient_connection_is_connected(conn);
  if (ret != 1) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "Failed to connect: %d\n", ret);
    goto exit;
  }

  ret = 0;
  goto exit;
exit: {
  atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_INFO, "test_13_is_connected End: %d\n", ret);
  return ret;
}
}

static int test_14_simulate_server_not_responding(atclient_connection *conn) {
  atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_INFO, "test_14_simulate_server_not_responding Begin\n");

  int ret = 1;

  // simulate server not responding
  ret = mbedtls_ssl_close_notify(&conn->ssl);
  if (ret != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "Failed to close notify: %d\n", ret);
    goto exit;
  }

  ret = 0;
  goto exit;
exit: {
  atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_INFO, "test_14_simulate_server_not_responding End: %d\n", ret);
  return ret;
}
}

static int test_15_send_should_fail(atclient_connection *conn) {
  atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_INFO, "test_15_send_should_fail\n");

  int ret = 1;

  const unsigned char *send_data = (const unsigned char *)"12alpaca\r\n";
  const size_t send_data_len = strlen((const char *)send_data);

  const size_t recvsize = 1024;
  unsigned char recv[recvsize];
  memset(recv, 0, recvsize);
  size_t recvlen = 0;

  ret = atclient_connection_send(conn, send_data, send_data_len, recv, recvsize, &recvlen);
  if (ret == 0) {
    ret = 1;
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR,
                 "Successfully sent message, when it should have been a failure. ret: %d\n", ret);
    goto exit;
  }

  atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_INFO, "Successfully failed at sending message to a disconnected connection: %d\n", ret);

  ret = 0;
  goto exit;
exit: {
  atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_INFO, "test_15_send_should_fail End: %d\n", ret);
  return ret;
}
}

static int test_16_is_connected_should_be_false(atclient_connection *conn) {
  atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_INFO, "test_16_is_connected_should_be_false Begin\n");

  int ret;

  ret = atclient_connection_is_connected(conn);
  if (ret == 1) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR,
                 "atclient_connection_is_connected returned true when it should have been false: %d\n", ret);
    goto exit;
  }

  atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_INFO, "Connection is not connected, as expected: %d\n", ret);

  ret = 0;
  goto exit;
exit: {
  atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_INFO, "test_16_is_connected_should_be_false End: %d\n", ret);
  return ret;
}
}

static int test_17_should_be_connected_should_be_true(atclient_connection *conn) {
  atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_INFO, "test_17_should_be_connected_should_be_true Begin\n");

  int ret = 1;

  if ((ret = assert_equals(conn->should_be_connected, true)) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "conn->should_be_connected should be true, but is false\n");
    goto exit;
  }
  atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_INFO, "conn->should_be_connected is true, as expected\n");

  ret = 0;
  goto exit;
exit: {
  atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_INFO, "test_17_should_be_connected_should_be_true End: %d\n", ret);
  return ret;
}
}
