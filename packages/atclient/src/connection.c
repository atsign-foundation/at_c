#include "atclient/connection.h"
#include "atchops/constants.h"
#include "atclient/cacerts.h"
#include "atclient/connection_hooks.h"
#include "atclient/constants.h"
#include "atlogger/atlogger.h"
#include "atclient/mbedtls.h"
#include <stdbool.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define TAG "connection"

/* Concatenation of all available CA certificates in PEM format */
static const char cas_pem[] = LETS_ENCRYPT_ROOT GOOGLE_GLOBAL_SIGN GOOGLE_GTS_ROOT_R1 GOOGLE_GTS_ROOT_R2
    GOOGLE_GTS_ROOT_R3 GOOGLE_GTS_ROOT_R4 ZEROSSL_INTERMEDIATE "";
static const size_t cas_pem_len = sizeof(cas_pem);

static void my_debug(void *ctx, int level, const char *file, int line, const char *str);

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
  ctx->_is_host_initialized = false;
  ctx->host = NULL;
  ctx->_is_port_initialized = false;
  ctx->port = 0;
  ctx->_is_connection_enabled = false;
  ctx->_is_hooks_enabled = false;
  ctx->hooks = NULL;
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
   * 2. Variables
   */
  const size_t recv_size = 256;
  unsigned char recv[recv_size];
  memset(recv, 0, sizeof(unsigned char) * recv_size);
  size_t recv_len = 0;

  const size_t port_str_size = 6;
  char port_str[port_str_size];

  /*
   * 3. Disable and Reenable connection
   */
  if (atclient_connection_is_connection_enabled(ctx)) {
    atclient_connection_disable_connection(ctx);
  }

  atclient_connection_enable_connection(ctx);

  /*
   * 3. Parse CA certs
   */
  if ((ret = mbedtls_x509_crt_parse(&(ctx->cacert), (unsigned char *)cas_pem, cas_pem_len)) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "mbedtls_x509_crt_parse failed with exit code: %d\n", ret);
    goto exit;
  }

  /*
   * 4. Seed the random number generator
   */
  if ((ret = mbedtls_ctr_drbg_seed(&(ctx->ctr_drbg), mbedtls_entropy_func, &(ctx->entropy),
                                   (unsigned char *)ATCHOPS_RNG_PERSONALIZATION,
                                   strlen(ATCHOPS_RNG_PERSONALIZATION))) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "mbedtls_ctr_drbg_seed failed with exit code: %d\n", ret);
    goto exit;
  }

  /*
   * 5. Start the socket connection
   */
  snprintf(port_str, port_str_size, "%d", port);
  if ((ret = mbedtls_net_connect(&(ctx->net), host, port_str, MBEDTLS_NET_PROTO_TCP)) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "mbedtls_net_connect failed with exit code: %d\n", ret);
    goto exit;
  }

  /*
   * 6. Prepare the SSL connection
   */
  if ((ret = mbedtls_ssl_config_defaults(&(ctx->ssl_config), MBEDTLS_SSL_IS_CLIENT, MBEDTLS_SSL_TRANSPORT_STREAM,
                                         MBEDTLS_SSL_PRESET_DEFAULT)) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "mbedtls_ssl_config_defaults failed with exit code: %d\n", ret);
    goto exit;
  }

  mbedtls_ssl_conf_ca_chain(&(ctx->ssl_config), &(ctx->cacert), NULL);
  mbedtls_ssl_conf_authmode(&(ctx->ssl_config), MBEDTLS_SSL_VERIFY_REQUIRED);
  mbedtls_ssl_conf_rng(&(ctx->ssl_config), mbedtls_ctr_drbg_random, &(ctx->ctr_drbg));
  mbedtls_ssl_conf_dbg(&(ctx->ssl_config), my_debug, stdout);
  mbedtls_ssl_conf_read_timeout(&(ctx->ssl_config),
                                ATCLIENT_CLIENT_READ_TIMEOUT_MS); // recv will timeout after X seconds

  if ((ret = mbedtls_ssl_setup(&(ctx->ssl), &(ctx->ssl_config))) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "mbedtls_ssl_setup failed with exit code: %d\n", ret);
    goto exit;
  }

  if ((ret = mbedtls_ssl_set_hostname(&(ctx->ssl), host)) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "mbedtls_ssl_set_hostname failed with exit code: %d\n", ret);
    goto exit;
  }

  mbedtls_ssl_set_bio(&(ctx->ssl), &(ctx->net), mbedtls_net_send, NULL, mbedtls_net_recv_timeout);

  /*
   * 7. Perform the SSL handshake
   */
  if ((ret = mbedtls_ssl_handshake(&(ctx->ssl))) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "mbedtls_ssl_handshake failed with exit code: %d\n", ret);
    goto exit;
  }

  /*
   * 7. Verify the server certificate
   */
  if ((ret = mbedtls_ssl_get_verify_result(&(ctx->ssl))) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "mbedtls_ssl_get_verify_result failed with exit code: %d\n", ret);
    goto exit;
  }

  // ===============
  // after connect
  // ===============

  // read anything that was already sent
  if ((ret = mbedtls_ssl_read(&(ctx->ssl), recv, recv_size)) <= 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "mbedtls_ssl_read failed with exit code: %d\n", ret);
    goto exit;
  }

  // press enter
  if ((ret = mbedtls_ssl_write(&(ctx->ssl), (const unsigned char *)"\r\n", strlen("\r\n"))) <= 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "mbedtls_ssl_write failed with exit code: %d\n", ret);
    goto exit;
  }

  // read anything that was sent
  memset(recv, 0, sizeof(unsigned char) * recv_size);
  if ((ret = mbedtls_ssl_read(&(ctx->ssl), recv, recv_size)) <= 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "mbedtls_ssl_read failed with exit code: %d\n", ret);
    goto exit;
  }

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
  goto exit;

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
    params.src = value;
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
  if ((ret = mbedtls_ssl_write(&(ctx->ssl), value, value_len)) <= 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "mbedtls_ssl_write failed with exit code: %d\n", ret);
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
                   reset);
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
  goto exit;
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
    params.src = src;
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
  if ((ret = mbedtls_ssl_write(&(ctx->ssl), src, src_len)) <= 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "mbedtls_ssl_write failed with exit code: %d\n", ret);
    goto exit;
  }

  /*
   * 5. Print debug log
   */
  if (atlogger_get_logging_level() >= ATLOGGER_LOGGING_LEVEL_DEBUG && ret == src_len) {
    unsigned char *srccopy = NULL;
    if ((srccopy = malloc(sizeof(unsigned char) * src_len)) != NULL) {
      memcpy(srccopy, src, src_len);
      atlogger_fix_stdout_buffer((char *)srccopy, src_len);
      atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_DEBUG, "\t%sSENT: %s\"%.*s\"%s\n", BBLU, HCYN, strlen((char *)srccopy),
                   srccopy, reset);
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
    params.src = src;
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
    params.src = src;
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
  int tries = 0;
  bool found = false;
  size_t l = 0;
  do {
    if ((ret = mbedtls_ssl_read(&(ctx->ssl), recv + l, recv_size - l)) <= 0) {
      atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "mbedtls_ssl_read failed with exit code: %d\n", ret);
      goto exit;
    }
    l = l + ret;
    for (int i = l; i >= l - ret && i >= 0; i--) {
      if (*(recv + i) == '\n' || *(recv + i) == '\r') {
        *recv_len = i;
        found = true;
        break;
      }
    }
    if (found) {
      break;
    }
  } while (ret == MBEDTLS_ERR_SSL_WANT_READ || ret == MBEDTLS_ERR_SSL_WANT_WRITE || ret == 0 || !found);
  recv[*recv_len] = '\0'; // null terminate the string

  /*
   * 10. Run post read hook, if it exists
   */
  if (try_hooks && atclient_connection_hooks_is_post_read_initialized(ctx)) {
    ctx->hooks->_is_nested_call = true;
    atclient_connection_hook_params params;
    params.src = src;
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
    if ((recvcopy = malloc(sizeof(unsigned char) * (*recv_len))) != NULL) {
      memcpy(recvcopy, recv, *recv_len);
      atlogger_fix_stdout_buffer((char *)recvcopy, *recv_len);
      atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_DEBUG, "\t%sRECV: %s\"%.*s\"%s\n", BMAG, HMAG, *recv_len, recvcopy,
                   reset);
      free(recvcopy);
    } else {
      atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR,
                   "Failed to allocate memory to pretty print the network received buffer\n");
    }
  }

  ret = 0;
  goto exit;
exit: {
  return ret;
}
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

  do {
    ret = mbedtls_ssl_close_notify(&(ctx->ssl));
  } while (ret == MBEDTLS_ERR_SSL_WANT_WRITE || ret == MBEDTLS_ERR_SSL_WANT_READ || ret != 0);

  atclient_connection_disable_connection(ctx);

  ret = 0;
  goto exit;
exit: { return ret; }
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
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "recv_len is <= 0, connection did not respond to \"%s\"\n", command);
    return false;
  }

  return true;
}

int atclient_connection_read(atclient_connection *ctx, unsigned char **value, size_t *value_len,
                             const size_t value_max_len) {
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

  if(!atclient_connection_is_connection_enabled(ctx)) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "Connection is not enabled\n");
    return ret;
  }

  /*
   * 2. Variables
   */
  size_t recv_size;
  if(value_max_len == 0) {
    // we read 4 KB at a time, TODO: make a constant
    recv_size = 4096;
  } else {
    recv_size = value_max_len;
  }
  unsigned char *recv = malloc(sizeof(unsigned char) * recv_size);

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
  bool found_end = false;
  size_t pos = 0;
  size_t recv_len = 0;
  do {
    if((ret = mbedtls_ssl_read(&(ctx->ssl), recv + pos, recv_size - pos)) <= 0) {
      atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "mbedtls_ssl_read failed with exit code: %d\n", ret);
      goto exit;
    }
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_DEBUG, "pos: %d, ret: %d\n", pos, ret);
    pos += ret;

    // check if we found the end of the message
    int i = pos;
    while(!found_end && i-- > 0) {
      found_end = recv[i] == '\n' || recv[i] == '\r';
    }

    if(found_end) {
      recv_len = i;
    } else {
      if(value_max_len != 0) {
        atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_WARN, "Message is too long, it exceeds the maximum length of %d\n", value_max_len);
        recv_len = value_max_len;
        break;
      } else {
        recv = realloc(recv, sizeof(unsigned char) * (pos + recv_size));
        recv_size += recv_size;
      }
    }

  } while(ret == MBEDTLS_ERR_SSL_WANT_READ || ret == MBEDTLS_ERR_SSL_WANT_WRITE || ret == 0 || !found_end);

  /*
   * 5. Print debug log
   */
  if(atlogger_get_logging_level() >= ATLOGGER_LOGGING_LEVEL_DEBUG) {
    unsigned char *recvcopy = NULL;
    if((recvcopy = malloc(sizeof(unsigned char) * recv_len)) != NULL) {
      memcpy(recvcopy, recv, recv_len);
      atlogger_fix_stdout_buffer((char *)recvcopy, recv_len);
      atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_DEBUG, "\t%sRECV: %s\"%.*s\"%s\n", BMAG, HMAG, recv_len, recvcopy, reset);
      free(recvcopy);
    } else {
      atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "Failed to allocate memory to pretty print the network received buffer\n");
    }
  }

  /*
   * 6. Set the value and value_len
   */
  if(found_end) {
    if(recv_len != 0 && recv_len < recv_size) {
      recv[recv_len] = '\0';
    }
  }
  if(value_len != NULL) {
      *value_len = recv_len;
    }
    if(value != NULL) {
      if((*value = malloc(sizeof(unsigned char) * (recv_len + 1))) == NULL) {
        ret = 1;
        atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "Failed to allocate memory for value\n");
        goto exit;
      }
      memcpy(*value, recv, recv_len);
      (*value)[recv_len] = '\0';
    }

  /*
   * 7. Call post_read hook, if it exists
   */
  if (try_hooks && atclient_connection_hooks_is_post_read_initialized(ctx) && ctx->hooks->post_read != NULL) {
    ctx->hooks->_is_nested_call = true;
    atclient_connection_hook_params params;
    params.src = NULL;
    params.src_len = 0;
    params.recv = recv;
    params.recv_size = recv_size;
    params.recv_len = &recv_len;
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

static void my_debug(void *ctx, int level, const char *file, int line, const char *str) {
  ((void)level);
  fprintf((FILE *)ctx, "%s:%04d: %s", file, line, str);
  fflush((FILE *)ctx);
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
  mbedtls_net_init(&(ctx->net));
  mbedtls_ssl_init(&(ctx->ssl));
  mbedtls_ssl_config_init(&(ctx->ssl_config));
  mbedtls_x509_crt_init(&(ctx->cacert));
  mbedtls_entropy_init(&(ctx->entropy));
  mbedtls_ctr_drbg_init(&(ctx->ctr_drbg));

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
  if (atclient_connection_is_connection_enabled(ctx)) {
    mbedtls_net_free(&(ctx->net));
    mbedtls_ssl_free(&(ctx->ssl));
    mbedtls_ssl_config_free(&(ctx->ssl_config));
    mbedtls_x509_crt_free(&(ctx->cacert));
    mbedtls_entropy_free(&(ctx->entropy));
    mbedtls_ctr_drbg_free(&(ctx->ctr_drbg));
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
