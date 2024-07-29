#include <atclient/connection.h>
#include <atclient/connection_hooks.h>
#include <atlogger/atlogger.h>
#include <string.h>

#define TAG "main"

#define HOST "3b419d7a-2fee-5080-9289-f0e1853abb47.swarm0002.atsign.zone"
#define PORT 5770

void *pre_read_hook(atclient_connection_hook_params *params) {
  atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_INFO, "pre_read_hook was called\n");
  // log params
  atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_DEBUG, "src (%p): \"%s\"\n", params->recv, (char *)params->src);
  atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_DEBUG, "src_len: %d\n", params->src_len);
  atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_DEBUG, "recv (%p): %s\n", params->recv, (char *)params->recv);
  if (params->recv_len != NULL) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_DEBUG, "recv_len: %d\n", *params->recv_len);
  } else {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_DEBUG, "recv_len: NULL\n");
  }
  atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_DEBUG, "recv_size: %d\n", params->recv_size);
  return NULL;
}

void *post_read_hook(atclient_connection_hook_params *params) {
  atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_INFO, "post_read_hook was called\n");
  // log params
  atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_DEBUG, "src (%p): \"%s\"\n", params->recv, (char *)params->src);
  atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_DEBUG, "src_len: %d\n", params->src_len);
  atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_DEBUG, "recv (%p): %s\n", params->recv, (char *)params->recv);
  if (params->recv_len != NULL) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_DEBUG, "recv_len: %d\n", *params->recv_len);
  } else {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_DEBUG, "recv_len: NULL\n");
  }
  atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_DEBUG, "recv_size: %d\n", params->recv_size);

  return NULL;
}

void *pre_write_hook(atclient_connection_hook_params *params) {
  atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_INFO, "pre_write_hook was called\n");
  // log params
  atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_DEBUG, "src (%p): \"%s\"\n", params->recv, (char *)params->src);
  atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_DEBUG, "src_len: %d\n", params->src_len);
  atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_DEBUG, "recv (%p): %s\n", params->recv, (char *)params->recv);
  if (params->recv_len != NULL) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_DEBUG, "recv_len: %d\n", *params->recv_len);
  } else {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_DEBUG, "recv_len: NULL\n");
  }
  atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_DEBUG, "recv_size: %d\n", params->recv_size);
  return NULL;
}

void *post_write_hook(atclient_connection_hook_params *params) {
  atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_INFO, "post_write_hook was called\n");
  // log params
  atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_DEBUG, "src (%p): \"%s\"\n", params->recv, (char *)params->src);
  atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_DEBUG, "src_len: %d\n", params->src_len);
  atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_DEBUG, "recv (%p): %s\n", params->recv, (char *)params->recv);
  if (params->recv_len != NULL) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_DEBUG, "recv_len: %d\n", *params->recv_len);
  } else {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_DEBUG, "recv_len: NULL\n");
  }
  atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_DEBUG, "recv_size: %d\n", params->recv_size);
  return NULL;
}

int main(int argc, char *argv[]) {
  int ret = 1;

  atlogger_set_logging_level(ATLOGGER_LOGGING_LEVEL_DEBUG);

  atclient_connection conn;
  atclient_connection_init(&conn, ATCLIENT_CONNECTION_TYPE_ATSERVER);

  const unsigned char *src = "from:12alpaca\r\n";
  const size_t src_len = strlen(src);
  unsigned char *recv = NULL;
  size_t recv_len = 0;

  if ((ret = atclient_connection_hooks_enable(&conn)) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "Failed to enable hooks\n");
    goto exit;
  }
  atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_INFO, "Enabled hooks\n");

  if ((ret = atclient_connection_hooks_set(&conn, ATCLIENT_CONNECTION_HOOK_TYPE_PRE_READ, pre_read_hook)) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "Failed to set pre_read hook\n");
    goto exit;
  }
  atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_INFO, "Set pre_read_hook successfully\n");

  if ((ret = atclient_connection_hooks_set(&conn, ATCLIENT_CONNECTION_HOOK_TYPE_POST_READ, post_read_hook)) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "Failed to set post_read hook\n");
    goto exit;
  }
  atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_INFO, "Set post_read_hook successfully\n");

  if ((ret = atclient_connection_hooks_set(&conn, ATCLIENT_CONNECTION_HOOK_TYPE_PRE_WRITE, pre_write_hook)) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "Failed to set pre_write hook\n");
    goto exit;
  }
  atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_INFO, "Set pre_write_hook successfully\n");

  if ((ret = atclient_connection_hooks_set(&conn, ATCLIENT_CONNECTION_HOOK_TYPE_POST_WRITE, post_write_hook)) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "Failed to set post_write hook\n");
    goto exit;
  }
  atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_INFO, "Set post_write_hook successfully\n");

  if ((ret = atclient_connection_connect(&conn, HOST, PORT)) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "Failed to connect to %s:%d\n", HOST, PORT);
    goto exit;
  }
  atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_INFO, "Connected to %s:%d\n", HOST, PORT);

  if ((ret = atclient_connection_write(&conn, (const unsigned char *)src, src_len)) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "Failed to write to %s:%d\n", HOST, PORT);
    goto exit;
  }

  if ((ret = atclient_connection_write(&conn, (const unsigned char *)src, src_len)) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "Failed to write to %s:%d\n", HOST, PORT);
    goto exit;
  }

  if ((ret = atclient_connection_read(&conn, &recv, &recv_len, 20)) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "Failed to read from %s:%d\n", HOST, PORT);
    goto exit;
  }

  if ((ret = atclient_connection_read(&conn, &recv, &recv_len, 20)) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "Failed to read from %s:%d\n", HOST, PORT);
    goto exit;
  }

  if ((ret = atclient_connection_read(&conn, &recv, &recv_len, 20)) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "Failed to read from %s:%d\n", HOST, PORT);
    goto exit;
  }

  if ((ret = atclient_connection_read(&conn, &recv, &recv_len, 0)) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "Failed to read from %s:%d\n", HOST, PORT);
    goto exit;
  }

  if ((ret = atclient_connection_disconnect(&conn)) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "Failed to disconnect from %s:%d\n", HOST, PORT);
    goto exit;
  }
  atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_INFO, "Disconnected from %s:%d\n", HOST, PORT);

  ret = 0;
  goto exit;
exit: {
  atclient_connection_free(&conn);
  return ret;
}
}