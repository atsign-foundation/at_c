#include "atclient/connection.h"
#include "atclient/atclient_utils.h"
#include "atclient/connection_hooks.h"
#include "atclient/constants.h"
#include "atclient/socket.h"
#include "atclient/string_utils.h"
#include "atlogger/atlogger.h"
#include <atchops/platform.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define TAG "connection"

static void atclient_connection_set_is_connection_enabled(atclient_connection *ctx, const bool should_be_connected);
static bool atclient_connection_is_connection_enabled(const atclient_connection *ctx);
static void atclient_connection_enable_connection(atclient_connection *ctx);
static void atclient_connection_disable_connection(atclient_connection *ctx);

static void atclient_connection_set_is_host_initialized(atclient_connection *ctx, const bool is_host_initialized);
static bool atclient_connection_is_host_initialized(const atclient_connection *ctx);
static int atclient_connection_set_host(atclient_connection *ctx, const char *host);
static void atclient_connection_unset_host(atclient_connection *ctx);

static void atclient_connection_set_is_port_initialized(atclient_connection *ctx, const bool is_port_initialized);
static bool atclient_connection_is_port_initialized(const atclient_connection *ctx);
static int atclient_connection_set_port(atclient_connection *ctx, const uint16_t port);
static void atclient_connection_unset_port(atclient_connection *ctx);

void atclient_connection_init(atclient_connection *ctx, atclient_connection_type type) {
  memset(ctx, 0, sizeof(atclient_connection));
  ctx->type = type;
}

void atclient_connection_free(atclient_connection *ctx) {
  if (atclient_connection_is_connection_enabled(ctx)) {
    atclient_connection_disable_connection(ctx);
  }
  if (atclient_connection_hooks_is_enabled(ctx)) {
    atclient_connection_hooks_disable(ctx);
  }
  if (atclient_connection_is_host_initialized(ctx)) {
    atclient_connection_unset_host(ctx);
  }
  if (atclient_connection_is_port_initialized(ctx)) {
    atclient_connection_unset_port(ctx);
  }
  memset(ctx, 0, sizeof(atclient_connection));
}

int atclient_connection_connect(atclient_connection *ctx, const char *host, const uint16_t port) {
  int ret = 1;

  /*
   * 1. Validate arguments
   */
  if (ctx == NULL) {
    ret = 1;
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "ctx is NULL\n");
    return ret;
  }

  if (host == NULL) {
    ret = 1;
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "host is NULL\n");
    return ret;
  }

  /*
   * 2. Disable and Reenable connection
   */
  if (atclient_connection_is_connection_enabled(ctx)) {
    atclient_connection_disable_connection(ctx);
  }

  atclient_connection_enable_connection(ctx);

  // 3. Setup ssl configuration
  ret = atclient_tls_socket_configure(&ctx->_socket, NULL, 0);
  if (ret != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "failed to setup ssl configuration\n");
    return ret;
  }

  ret = atclient_tls_socket_connect(&ctx->_socket, host, port);
  if (ret != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "failed to connect to %s:%u\n", host, port);
    return ret;
  }

  atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_INFO, "Connected\n");

  // ===============
  // after connect
  // ===============

  // read anything that was already sent

  // FIXME: temporary hack to adapt TLS socket read's heap allocated reading to
  // the existing functions which expect stack allocated memory
  // all callers of this function should support dynamic memory allocations
  // to ensure we are able to read the result in full
  // the atclient_tls_socket_read function has a built in limit
  unsigned char *buf1, *buf2;
  size_t n1, n2;
  ret = atclient_tls_socket_read(&ctx->_socket, &buf1, &n1, atclient_socket_read_until_char('@'));
  if (ret != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "Failed to read from the connection\n", ret);
    goto exit;
  }
  free(buf1);

  if ((ret = atclient_tls_socket_write(&(ctx->_socket), (const unsigned char *)"\r\n", strlen("\r\n"))) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atclient_tls_socket_write failed with exit code: %d\n", ret);
    goto exit;
  }

  ret = atclient_tls_socket_read(&ctx->_socket, &buf2, &n2, atclient_socket_read_until_char('@'));
  if (ret != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "Failed to read from the connection\n", ret);
    goto exit;
  }
  free(buf2);

  // now we are guaranteed a blank canvas

  if ((ret = atclient_connection_set_host(ctx, host)) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atclient_connection_set_host failed with exit code: %d\n", ret);
    goto exit;
  }

  if ((ret = atclient_connection_set_port(ctx, port)) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atclient_connection_set_port failed with exit code: %d\n", ret);
    goto exit;
  }

  ret = 0;

exit: {
  if (ret != 0) {
    atclient_connection_disable_connection(ctx);
  }
  return ret;
}
}

int atclient_connection_write(atclient_connection *ctx, const unsigned char *value, const size_t value_len) {
  int ret = 1;

  /*
   * 1. Validate arguments
   */
  if (ctx == NULL) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "ctx is NULL\n");
    goto exit;
  }

  if (value == NULL) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "value is NULL\n");
    goto exit;
  }

  if (value_len == 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "value_len is 0\n");
    goto exit;
  }

  if (!atclient_connection_is_connection_enabled(ctx)) {
    ret = 1;
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "Connection is not enabled\n");
    goto exit;
  }

  /*
   * 2. Call pre_write hook, if it exists
   */
  bool try_hooks = atclient_connection_hooks_is_enabled(ctx) && ctx->hooks != NULL && !ctx->hooks->_is_nested_call;
  if (try_hooks && atclient_connection_hooks_is_pre_write_initialized(ctx) && ctx->hooks->pre_write != NULL) {
    ctx->hooks->_is_nested_call = true;
    atclient_connection_hook_params params;
    params.src = (unsigned char *)value;
    params.src_len = value_len;
    params.recv = NULL;
    params.recv_size = 0;
    params.recv_len = NULL;
    ret = ctx->hooks->pre_write(&params);
    if (ctx->hooks != NULL) {
      ctx->hooks->_is_nested_call = false;
    }
    if (ret != 0) {
      atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "pre_write hook failed with exit code: %d\n", ret);
      goto exit;
    }
  }

  /*
   * 2. Write the value
   */
  if ((ret = atclient_tls_socket_write(&ctx->_socket, value, value_len)) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atclient_tls_socket_write failed with exit code: %d\n", ret);
    goto exit;
  }

  /*
   * 3. Print debug log
   */
  if (atlogger_get_logging_level() >= ATLOGGER_LOGGING_LEVEL_DEBUG) {
    unsigned char *valuecopy = malloc(sizeof(unsigned char) * value_len);
    if (valuecopy != NULL) {
      memcpy(valuecopy, value, value_len);
      atlogger_fix_stdout_buffer((char *)valuecopy, value_len);
      atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_DEBUG, "\t%sSENT: %s\"%.*s\"%s\n", BBLU, HCYN, value_len, valuecopy,
                   ATCLIENT_RESET);
      free(valuecopy);
    } else {
      atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR,
                   "Failed to allocate memory to pretty print the network sent transmission\n");
    }
  }

  /*
   * 4. Call hooks, if they exist
   */
  if (try_hooks && atclient_connection_hooks_is_post_write_initialized(ctx) && ctx->hooks->post_write != NULL) {
    ctx->hooks->_is_nested_call = true;
    atclient_connection_hook_params params;
    params.src = (unsigned char *)value;
    params.src_len = value_len;
    params.recv = NULL;
    params.recv_size = 0;
    params.recv_len = NULL;
    ret = ctx->hooks->post_write(&params);
    if (ctx->hooks != NULL) {
      ctx->hooks->_is_nested_call = false;
    }
    if (ret != 0) {
      atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "post_recv hook failed with exit code: %d\n", ret);
      goto exit;
    }
  }

  ret = 0;
exit: { return ret; }
}

int atclient_connection_send(atclient_connection *ctx, const unsigned char *src, const size_t src_len,
                             unsigned char *recv, const size_t recv_size, size_t *recv_len) {
  int ret = 1;

  /*
   * 1. Validate arguments
   */
  if (ctx == NULL) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "ctx is NULL\n");
    return ret;
  }

  if (src == NULL) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "src is NULL\n");
    return ret;
  }

  if (src_len == 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "srclen is 0\n");
    return ret;
  }

  if (!atclient_connection_is_connection_enabled(ctx)) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "Connection is not enabled\n");
    return ret;
  }

  /*
   * 3. Call pre_send hook, if it exists
   */
  bool try_hooks = atclient_connection_hooks_is_enabled(ctx) && !ctx->hooks->_is_nested_call;
  if (try_hooks && atclient_connection_hooks_is_pre_write_initialized(ctx)) {
    ctx->hooks->_is_nested_call = true;
    atclient_connection_hook_params params;
    params.src = (unsigned char *)src;
    params.src_len = src_len;
    params.recv = recv;
    params.recv_size = recv_size;
    params.recv_len = recv_len;
    ret = ctx->hooks->pre_write(&params);
    if (ctx->hooks != NULL) {
      ctx->hooks->_is_nested_call = false;
    }
    if (ret != 0) {
      atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "pre_send hook failed with exit code: %d\n", ret);
      goto exit;
    }
  }

  /*
   * 4. Write the value
   */
  if (src[src_len - 1] != '\n') {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_WARN, "command does not have a trailing \\n character:\t%s\n", src);
  }

  if ((ret = atclient_tls_socket_write(&ctx->_socket, src, src_len)) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atclient_tls_socket_write failed with exit code: %d\n", ret);
    goto exit;
  }

  /*
   * 5. Print debug log
   */
  if (atlogger_get_logging_level() >= ATLOGGER_LOGGING_LEVEL_DEBUG) {
    unsigned char *srccopy = NULL;
    if ((srccopy = malloc(sizeof(unsigned char) * src_len)) != NULL) {
      memcpy(srccopy, src, src_len);
      atlogger_fix_stdout_buffer((char *)srccopy, src_len);
      atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_DEBUG, "\t%sSENT: %s\"%.*s\"%s\n", BBLU, HCYN, strlen((char *)srccopy),
                   srccopy, ATCLIENT_RESET);
      free(srccopy);
    } else {
      atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR,
                   "Failed to allocate memory to pretty print the network sent transmission\n");
    }
  }

  /*
   * 6. Call post_send hook, if it exists
   */
  if (try_hooks && atclient_connection_hooks_is_post_write_initialized(ctx)) {
    ctx->hooks->_is_nested_call = true;
    atclient_connection_hook_params params;
    params.src = (unsigned char *)src;
    params.src_len = src_len;
    params.recv = recv;
    params.recv_size = recv_size;
    params.recv_len = recv_len;
    ret = ctx->hooks->post_write(&params);
    if (ctx->hooks != NULL) {
      ctx->hooks->_is_nested_call = false;
    }
    if (ret != 0) {
      atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "post_send hook failed with exit code: %d\n", ret);
      goto exit;
    }
  }

  /*
   * 7. Exit if recv is NULL
   */
  if (recv == NULL) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "recv is null. exiting\n");
    ret = 0;
    goto exit;
  }

  /*
   * 8. Run pre read hook, if it exists
   */
  memset(recv, 0, sizeof(unsigned char) * recv_size);
  if (try_hooks && atclient_connection_hooks_is_pre_read_initialized(ctx)) {
    ctx->hooks->_is_nested_call = true;
    atclient_connection_hook_params params;
    params.src = (unsigned char *)src;
    params.src_len = src_len;
    params.recv = recv;
    params.recv_size = recv_size;
    params.recv_len = recv_len;
    ret = ctx->hooks->pre_read(&params);
    if (ctx->hooks != NULL) {
      ctx->hooks->_is_nested_call = false;
    }
    if (ret != 0) {
      atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "pre_recv hook failed with exit code: %d\n", ret);
      goto exit;
    }
  }

  /*
   * 9. Read the value
   */

  // FIXME: temporary hack to adapt TLS socket read's heap allocated reading to
  // the existing functions which expect stack allocated memory
  // all callers of this function should support dynamic memory allocations
  // to ensure we are able to read the result in full
  // the atclient_tls_socket_read function has a built in limit
  unsigned char *read_buf;
  size_t read_n;
  ret = atclient_tls_socket_read(&ctx->_socket, &read_buf, &read_n, atclient_socket_read_until_char('\n'));
  if (ret != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "Failed to read from the connection\n", ret);
    goto exit;
  }

  size_t read_i = 0; // will store where the start of `<type>:` is (if happy path)
  ret = atclient_utils_find_index_past_at_prompt(read_buf, read_n, &read_i);
  if (ret != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "Failed to parse the result read from the connection\n");
    free(read_buf);
    goto exit;
  }
  if (read_n - read_i > recv_size) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR,
                 "Read amount exceeds the stack allocated limit (will be fixed in a future update)\n");
    free(read_buf);
    goto exit;
  }
  read_n -= read_i;
  // copy to recv, discarding the prompt
  memcpy(recv, read_buf + read_i, read_n);
  free(read_buf);
  recv[read_n - 1] = '\0'; // null terminate the string
  *recv_len = read_n;

  /*
   * 10. Run post read hook, if it exists
   */
  if (try_hooks && atclient_connection_hooks_is_post_read_initialized(ctx)) {
    ctx->hooks->_is_nested_call = true;
    atclient_connection_hook_params params;
    params.src = (unsigned char *)src;
    params.src_len = src_len;
    params.recv = recv;
    params.recv_size = recv_size;
    params.recv_len = recv_len;
    ret = ctx->hooks->post_read(&params);
    if (ctx->hooks != NULL) {
      ctx->hooks->_is_nested_call = false;
    }
    if (ret != 0) {
      atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "post_recv hook failed with exit code: %d\n", ret);
      goto exit;
    }
  }

  /*
   * 11. Print debug log
   */
  if (atlogger_get_logging_level() >= ATLOGGER_LOGGING_LEVEL_DEBUG) {
    unsigned char *recvcopy = NULL;
    if ((recvcopy = malloc(sizeof(unsigned char) * *recv_len)) != NULL) {
      memcpy(recvcopy, recv, *recv_len);
      atlogger_fix_stdout_buffer((char *)recvcopy, *recv_len);
      atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_DEBUG, "\t%sRECV: %s\"%.*s\"%s\n", BMAG, HMAG, *recv_len, recvcopy,
                   ATCLIENT_RESET);
      free(recvcopy);
    } else {
      atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR,
                   "Failed to allocate memory to pretty print the network received buffer\n");
    }
  }

  ret = 0;
  goto exit;
exit: { return ret; }
}

int atclient_connection_disconnect(atclient_connection *ctx) {
  int ret = 1;

  /*
   * 1. Validate arguments
   */
  if (ctx == NULL) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "ctx is NULL\n");
    return ret;
  }

  if (!atclient_connection_is_connection_enabled(ctx)) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "Connection is not enabled\n");
    return ret;
  }

  // intentionally disregarding the return value
  atclient_tls_socket_disconnect(&ctx->_socket);

  atclient_connection_disable_connection(ctx);

  return 0;
}

bool atclient_connection_is_connected(atclient_connection *ctx) {

  /*
   * 1. Validate arguments
   */
  if (ctx == NULL) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "ctx is NULL, of course it's not connected lol\n");
    return false;
  }

  if (!atclient_connection_is_connection_enabled(ctx)) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "Connection is not enabled\n");
    return false;
  }

  char *command = NULL;
  if (ctx->type == ATCLIENT_CONNECTION_TYPE_ATSERVER) {
    command = "noop:0\r\n";
  } else if (ctx->type == ATCLIENT_CONNECTION_TYPE_ATDIRECTORY) {
    command = "\n";
  } else {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR,
                 "ctx->type is not ATCLIENT_CONNECTION_TYPE_ATSERVER or ATCLIENT_CONNECTION_TYPE_ROOT\n");
    return false;
  }

  const size_t commandlen = strlen(command);

  const size_t recvsize = 64;
  unsigned char recv[recvsize];
  size_t recv_len;

  int ret = atclient_connection_send(ctx, (unsigned char *)command, commandlen, recv, recvsize, &recv_len);
  if (ret != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "Failed to send \"%s\" to connection: %d\n", command, ret);
    return false;
  }

  if (recv_len <= 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "recv_len is <= 0, connection did not respond to \"%s\"\n",
                 command);
    return false;
  }

  return true;
}

int atclient_connection_read(atclient_connection *ctx, unsigned char **value, size_t *value_len) {
  int ret = 1;

  /*
   * 1. Validate arguments
   */
  if (ctx == NULL) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "ctx is NULL\n");
    return ret;
  }

  if (value == NULL) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "value is NULL\n");
    return ret;
  }

  if (!atclient_connection_is_connection_enabled(ctx)) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "Connection is not enabled\n");
    return ret;
  }

  /*
   * 3. Call pre_read hook, if it exists
   */
  bool try_hooks = atclient_connection_hooks_is_enabled(ctx) && ctx->hooks != NULL && !ctx->hooks->_is_nested_call;
  if (try_hooks && atclient_connection_hooks_is_pre_read_initialized(ctx) && ctx->hooks->pre_read != NULL) {
    ctx->hooks->_is_nested_call = true;
    atclient_connection_hook_params params;
    params.src = NULL;
    params.src_len = 0;
    params.recv = NULL;
    params.recv_size = 0;
    params.recv_len = NULL;
    ret = ctx->hooks->pre_read(&params);
    if (ctx->hooks != NULL) {
      ctx->hooks->_is_nested_call = false;
    }
    if (ret != 0) {
      atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "pre_read hook failed with exit code: %d\n", ret);
      goto exit;
    }
  }

  /*
   * 4. Read the value
   */
  unsigned char *read_buf;
  size_t read_n;
  ret = atclient_tls_socket_read(&ctx->_socket, &read_buf, &read_n, atclient_socket_read_until_char('\n'));
  if (ret != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "Failed to read from the connection\n", ret);
    goto exit;
  }
  size_t read_i = 0; // will store where the start of `<type>:` is (if happy path)
  ret = atclient_utils_find_index_past_at_prompt(*value, *value_len, &read_i);
  if (ret != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "Failed to parse the result read from the connection\n");
    free(read_buf);
    goto exit;
  }
  read_n -= read_i;
  *value = malloc(read_n * sizeof(char));
  if (*value == NULL) {
    free(read_buf);
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "Failed to allocate memory for the final output buffer\n");
    goto exit;
  }
  memcpy(*value, read_buf + read_i, read_n);
  free(read_buf);
  *value[read_n - 1] = '\0'; // null terminate the string
  *value_len = read_n;

  /*
   * 5. Print debug log
   */
  if (atlogger_get_logging_level() >= ATLOGGER_LOGGING_LEVEL_DEBUG) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_DEBUG, "\t%sRECV: %s\"%.*s\"%s\n", BMAG, HMAG, *value_len, *value,
                 ATCLIENT_RESET);
  }

  /*
   * 7. Call post_read hook, if it exists
   */
  if (try_hooks && atclient_connection_hooks_is_post_read_initialized(ctx) && ctx->hooks->post_read != NULL) {
    ctx->hooks->_is_nested_call = true;
    atclient_connection_hook_params params;
    params.src = NULL;
    params.src_len = 0;
    params.recv = *value;
    params.recv_size = *value_len;
    params.recv_len = value_len;
    ret = ctx->hooks->post_read(&params);
    if (ctx->hooks != NULL) {
      ctx->hooks->_is_nested_call = false;
    }
    if (ret != 0) {
      atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "post_read hook failed with exit code: %d\n", ret);
      goto exit;
    }
  }

  ret = 0;
  goto exit;
exit: { return ret; }
}

void atclient_connection_set_read_timeout(atclient_connection *ctx, const uint32_t timeout_ms) {
  if (ctx == NULL) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "ctx is NULL\n");
    return;
  }
  atclient_tls_socket_set_read_timeout(&ctx->_socket, timeout_ms);
}

static void atclient_connection_set_is_connection_enabled(atclient_connection *ctx, const bool should_be_connected) {
  ctx->_is_connection_enabled = should_be_connected;
}

static bool atclient_connection_is_connection_enabled(const atclient_connection *ctx) {
  return ctx->_is_connection_enabled;
}

static void atclient_connection_enable_connection(atclient_connection *ctx) {
  /*
   * 1. Validate arguments
   */
  if (ctx == NULL) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "ctx is NULL\n");
    return;
  }

  /*
   * 2. Disable connection, if necessary
   */
  if (atclient_connection_is_connection_enabled(ctx)) {
    atclient_connection_disable_connection(ctx);
  }

  /*
   * 3. Enable the connection
   */
  atclient_tls_socket_init(&ctx->_socket);

  /*
   * 4. Set the connection enabled flag
   */
  atclient_connection_set_is_connection_enabled(ctx, true);
}

static void atclient_connection_disable_connection(atclient_connection *ctx) {
  /*
   * 1. Validate arguments
   */
  if (ctx == NULL) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "ctx is NULL\n");
    return;
  }

  /*
   * 2. Free the contexts
   */
  // This is bad behavior for portability
  // We should not free the whole socket
  if (atclient_connection_is_connection_enabled(ctx)) {
    atclient_tls_socket_free(&ctx->_socket);
  }

  /*
   * 3. Set the connection disabled flag
   */
  atclient_connection_set_is_connection_enabled(ctx, false);
}

static void atclient_connection_set_is_host_initialized(atclient_connection *ctx, const bool is_host_initialized) {
  /*
   * 1. Validate arguments
   */
  if (ctx == NULL) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "ctx is NULL\n");
    return;
  }

  /*
   * 2. Set the host initialized flag
   */
  ctx->_is_host_initialized = is_host_initialized;
}

static bool atclient_connection_is_host_initialized(const atclient_connection *ctx) {
  /*
   * 1. Validate arguments
   */
  if (ctx == NULL) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "ctx is NULL\n");
    return false;
  }

  /*
   * 2. Return the host initialized flag
   */
  return ctx->_is_host_initialized;
}

static int atclient_connection_set_host(atclient_connection *ctx, const char *host) {
  int ret = 1;

  /*
   * 1. Validate arguments
   */
  if (ctx == NULL) {
    ret = 1;
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "ctx is NULL\n");
    return ret;
  }

  if (host == NULL) {
    ret = 1;
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "host is NULL\n");
    return ret;
  }

  /*
   * 2. Allocate memory for the host
   */
  const size_t host_len = strlen(host);
  const size_t host_size = host_len + 1;
  if ((ctx->host = malloc(sizeof(char) * host_size)) == NULL) {
    ret = 1;
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "Failed to allocate memory for host\n");
    goto exit;
  }

  /*
   * 3. Copy the host
   */
  memcpy(ctx->host, host, host_len);
  ctx->host[host_len] = '\0';

  /*
   * 4. Set the host initialized flag
   */
  atclient_connection_set_is_host_initialized(ctx, true);

  ret = 0;
  goto exit;
exit: { return ret; }
}

static void atclient_connection_unset_host(atclient_connection *ctx) {
  /*
   * 1. Validate arguments
   */
  if (ctx == NULL) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "ctx is NULL\n");
    return;
  }

  /*
   * 2. Free the host
   */
  if (atclient_connection_is_host_initialized(ctx)) {
    free(ctx->host);
  }
  ctx->host = NULL;

  /*
   * 3. Unset the host initialized flag
   */
  atclient_connection_set_is_host_initialized(ctx, false);
}

static void atclient_connection_set_is_port_initialized(atclient_connection *ctx, const bool is_port_initialized) {
  /*
   * 1. Validate arguments
   */
  if (ctx == NULL) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "ctx is NULL\n");
    return;
  }

  /*
   * 2. Set the port initialized flag
   */
  ctx->_is_port_initialized = is_port_initialized;
}

static bool atclient_connection_is_port_initialized(const atclient_connection *ctx) {
  /*
   * 1. Validate arguments
   */
  if (ctx == NULL) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "ctx is NULL\n");
    return false;
  }

  /*
   * 2. Return the port initialized flag
   */
  return ctx->_is_port_initialized;
}

static int atclient_connection_set_port(atclient_connection *ctx, const uint16_t port) {
  int ret = 1;

  /*
   * 1. Validate arguments
   */
  if (ctx == NULL) {
    ret = 1;
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "ctx is NULL\n");
    return ret;
  }

  if (port < 0) {
    ret = 1;
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "port is less than 0\n");
    return ret;
  }

  /*
   * 2. Set the port
   */
  ctx->port = port;

  /*
   * 3. Set the port initialized flag
   */
  atclient_connection_set_is_port_initialized(ctx, true);

  ret = 0;
  goto exit;
exit: { return ret; }
}

static void atclient_connection_unset_port(atclient_connection *ctx) {
  /*
   * 1. Validate arguments
   */
  if (ctx == NULL) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "ctx is NULL\n");
    return;
  }

  /*
   * 2. Unset the port
   */
  ctx->port = 0;

  /*
   * 3. Unset the port initialized flag
   */
  atclient_connection_set_is_port_initialized(ctx, false);
}
