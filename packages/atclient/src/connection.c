#include "atclient/connection.h"
#include "atchops/constants.h"
#include "atclient/atstr.h"
#include "atclient/cacerts.h"
#include "atclient/constants.h"
#include "atlogger/atlogger.h"
#include <mbedtls/ctr_drbg.h>
#include <mbedtls/entropy.h>
#include <mbedtls/net_sockets.h>
#include <mbedtls/ssl.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define TAG "connection"

/* Concatenation of all available CA certificates in PEM format */
const char cas_pem[] = LETS_ENCRYPT_ROOT GOOGLE_GLOBAL_SIGN GOOGLE_GTS_ROOT_R1 GOOGLE_GTS_ROOT_R2 GOOGLE_GTS_ROOT_R3
    GOOGLE_GTS_ROOT_R4 ZEROSSL_INTERMEDIATE "";
const size_t cas_pem_len = sizeof(cas_pem);

static void my_debug(void *ctx, int level, const char *file, int line, const char *str) {
  ((void)level);
  fprintf((FILE *)ctx, "%s:%04d: %s", file, line, str);
  fflush((FILE *)ctx);
}

static void init_contexts(atclient_connection *ctx) {
  mbedtls_net_init(&(ctx->net));
  mbedtls_ssl_init(&(ctx->ssl));
  mbedtls_ssl_config_init(&(ctx->ssl_config));
  mbedtls_x509_crt_init(&(ctx->cacert));
  mbedtls_entropy_init(&(ctx->entropy));
  mbedtls_ctr_drbg_init(&(ctx->ctr_drbg));
}

static void free_contexts(atclient_connection *ctx) {
  mbedtls_net_free(&(ctx->net));
  mbedtls_ssl_free(&(ctx->ssl));
  mbedtls_ssl_config_free(&(ctx->ssl_config));
  mbedtls_x509_crt_free(&(ctx->cacert));
  mbedtls_entropy_free(&(ctx->entropy));
  mbedtls_ctr_drbg_free(&(ctx->ctr_drbg));
}

void atclient_connection_init(atclient_connection *ctx, atclient_connection_type type) {

  if (ctx == NULL) {
    return; // how should we handle this error?
  }

  memset(ctx, 0, sizeof(atclient_connection));
  memset(ctx->host, 0, ATCLIENT_CONSTANTS_HOST_BUFFER_SIZE);
  ctx->port = -1;
  ctx->should_be_connected = false;
  ctx->type = type;
}

int atclient_connection_connect(atclient_connection *ctx, const char *host, const int port) {
  int ret = 1;

  if (ctx->should_be_connected) {
    atclient_connection_disconnect(ctx);
  }

  init_contexts(ctx);
  ctx->should_be_connected = true;

  const size_t readbufsize = 1024;
  unsigned char readbuf[readbufsize];
  memset(readbuf, 0, sizeof(unsigned char) * readbufsize);
  size_t readbuflen = 0;

  /*
   * 1. Set the ctx->host and ctx->port
   */
  memcpy(ctx->host, host, strlen(host)); // assume null terminated, example: "root.atsign.org"
  ctx->port = port;                      // example: 64

  char portstr[6];
  sprintf(portstr, "%d", ctx->port);

  /*
   * 2. Parse CA certs
   */
  ret = mbedtls_x509_crt_parse(&(ctx->cacert), (unsigned char *)cas_pem, cas_pem_len);
  if (ret != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "mbedtls_x509_crt_parse failed with exit code: %d\n", ret);
    goto exit;
  }

  /*
   * 3. Seed the random number generator
   */

  ret = mbedtls_ctr_drbg_seed(&(ctx->ctr_drbg), mbedtls_entropy_func, &(ctx->entropy),
                              (unsigned char *)ATCHOPS_RNG_PERSONALIZATION, strlen(ATCHOPS_RNG_PERSONALIZATION));
  if (ret != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "mbedtls_ctr_drbg_seed failed with exit code: %d\n", ret);
    goto exit;
  }

  /*
   * 4. Start the socket connection
   */
  ret = mbedtls_net_connect(&(ctx->net), host, portstr, MBEDTLS_NET_PROTO_TCP);
  if (ret != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "mbedtls_net_connect failed with exit code: %d\n", ret);
    goto exit;
  }

  /*
   * 5. Prepare the SSL connection
   */
  ret = mbedtls_ssl_config_defaults(&(ctx->ssl_config), MBEDTLS_SSL_IS_CLIENT, MBEDTLS_SSL_TRANSPORT_STREAM,
                                    MBEDTLS_SSL_PRESET_DEFAULT);
  if (ret != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "mbedtls_ssl_config_defaults failed with exit code: %d\n", ret);
    goto exit;
  }

  mbedtls_ssl_conf_ca_chain(&(ctx->ssl_config), &(ctx->cacert), NULL);
  mbedtls_ssl_conf_authmode(&(ctx->ssl_config), MBEDTLS_SSL_VERIFY_REQUIRED);
  mbedtls_ssl_conf_rng(&(ctx->ssl_config), mbedtls_ctr_drbg_random, &(ctx->ctr_drbg));
  mbedtls_ssl_conf_dbg(&(ctx->ssl_config), my_debug, stdout);
  mbedtls_ssl_conf_read_timeout(&(ctx->ssl_config),
                                ATCLIENT_CLIENT_READ_TIMEOUT_MS); // recv will timeout after X seconds

  ret = mbedtls_ssl_setup(&(ctx->ssl), &(ctx->ssl_config));
  if (ret != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "mbedtls_ssl_setup failed with exit code: %d\n", ret);
    goto exit;
  }

  ret = mbedtls_ssl_set_hostname(&(ctx->ssl), host);
  if (ret != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "mbedtls_ssl_set_hostname failed with exit code: %d\n", ret);
    goto exit;
  }

  mbedtls_ssl_set_bio(&(ctx->ssl), &(ctx->net), mbedtls_net_send, NULL, mbedtls_net_recv_timeout);

  /*
   * 6. Perform the SSL handshake
   */
  ret = mbedtls_ssl_handshake(&(ctx->ssl));
  if (ret != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "mbedtls_ssl_handshake failed with exit code: %d\n", ret);
    goto exit;
  }

  /*
   * 7. Verify the server certificate
   */
  ret = mbedtls_ssl_get_verify_result(&(ctx->ssl));
  if (ret != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "mbedtls_ssl_get_verify_result failed with exit code: %d\n", ret);
    goto exit;
  }

  // ===============
  // after connect
  // ===============

  // read anything that was already sent
  ret = mbedtls_ssl_read(&(ctx->ssl), readbuf, readbufsize);
  if (ret < 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "mbedtls_ssl_read failed with exit code: %d\n", ret);
    goto exit;
  }

  // press enter
  ret = mbedtls_ssl_write(&(ctx->ssl), (const unsigned char *)"\r\n", 2);
  if (ret < 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "mbedtls_ssl_write failed with exit code: %d\n", ret);
    goto exit;
  }

  // read anything that was sent
  ret = mbedtls_ssl_read(&(ctx->ssl), readbuf, readbufsize);
  if (ret < 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "mbedtls_ssl_read failed with exit code: %d\n", ret);
    goto exit;
  }

  // now we are guaranteed a blank canvas

  if (ret > 0) {
    ret = 0; // a positive exit code is not an error
  }
  goto exit;

exit: {
  if (ret != 0) {
    // undo what we set
    memset(ctx->host, 0, ATCLIENT_CONSTANTS_HOST_BUFFER_SIZE);
    ctx->port = -1;
  }
  return ret;
}
}

int atclient_connection_send(atclient_connection *ctx, const unsigned char *src_r, const size_t srclen_r,
                             unsigned char *recv, const size_t recvsize_r, size_t *recvlen) {
  int ret = 1;

  // Clone readonly inputs so it is editable by the hooks
  size_t srclen = srclen_r;
  size_t recvsize = recvsize_r;

  bool try_hooks = ctx->hooks != NULL && !ctx->hooks->_is_nested_call;
  bool allocate_src = try_hooks && ctx->hooks->readonly_src == false;

  unsigned char *src;

  if (allocate_src) {
    src = malloc(sizeof(unsigned char) * srclen);
    if (src == NULL) {
      atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "Failed to allocate memory for src\n");
      allocate_src = false; // don't try to free since the memory failed to be allocated
      goto exit;
    }
    memcpy(src, src_r, srclen);
  } else {
    src = (unsigned char *)src_r;
  }

  if (!ctx->should_be_connected) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR,
                 "ctx->should_be_connected should be true, but is false. You are trying to send messages to a "
                 "non-connected connection.\n");
    goto exit;
  }

  if (try_hooks && ctx->hooks->pre_send != NULL) {
    ctx->hooks->_is_nested_call = true;
    ret = ctx->hooks->pre_send(src, srclen, recv, recvsize, recvlen);
    ctx->hooks->_is_nested_call = false;
    if (ret != 0) {
      atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "pre_send hook failed with exit code: %d\n", ret);
      goto exit;
    }
  }

  ret = mbedtls_ssl_write(&(ctx->ssl), src, srclen);
  if (ret <= 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "mbedtls_ssl_write failed with exit code: %d\n", ret);
    goto exit;
  }

  if (try_hooks && ctx->hooks->post_send != NULL) {
    ctx->hooks->_is_nested_call = true;
    ret = ctx->hooks->post_send(src, srclen, recv, recvsize, recvlen);
    ctx->hooks->_is_nested_call = false;
    if (ret != 0) {
      atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "post_send hook failed with exit code: %d\n", ret);
      goto exit;
    }
  }

  unsigned char *srccopy;
  if (atlogger_get_logging_level() >= ATLOGGER_LOGGING_LEVEL_DEBUG && ret == srclen) {
    srccopy = malloc(sizeof(unsigned char) * srclen);
    if (srccopy != NULL) {
      memcpy(srccopy, src, srclen);
      atlogger_fix_stdout_buffer((char *)srccopy, srclen);
      atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_DEBUG, "\t%sSENT: %s\"%.*s\"%s\n", BBLU, HCYN, strlen((char *)srccopy),
                   srccopy, reset);
      free(srccopy);
    } else {
      atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR,
                   "Failed to allocate memory to pretty print the network sent transmission\n");
    }
  }

  if (recv == NULL) {
    ret = 0;
    goto exit;
  }

  memset(recv, 0, sizeof(unsigned char) * recvsize);

  if (try_hooks && ctx->hooks->pre_recv != NULL) {
    ctx->hooks->_is_nested_call = true;
    ret = ctx->hooks->pre_recv(src, srclen, recv, recvsize, recvlen);
    ctx->hooks->_is_nested_call = false;
    if (ret != 0) {
      atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "pre_recv hook failed with exit code: %d\n", ret);
      goto exit;
    }
  }

  int tries = 0;
  bool found = false;
  size_t l = 0;
  do {
    ret = mbedtls_ssl_read(&(ctx->ssl), recv + l, recvsize - l);
    if (ret <= 0) {
      atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "mbedtls_ssl_read failed with exit code: %d\n", ret);
      goto exit;
    }
    if (ret == 0) {
      tries++;
      if (tries >= ATCLIENT_CONNECTION_MAX_READ_TRIES) {
        atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR,
                     "mbedtls_ssl_read tried to read %d times and found nothing: %d\n", tries, ret);
        ret = 1;
        goto exit;
      }
    }
    l = l + ret;

    for (int i = l; i >= l - ret && i >= 0; i--) {
      // printf("i: %d c: %.2x\n", i, (unsigned char) *(recv + i));
      if (*(recv + i) == '\n' || *(recv + i) == '\r') {
        *recvlen = i;
        found = true;
        break;
      }
    }
    if (found) {
      break;
    }

  } while (ret == MBEDTLS_ERR_SSL_WANT_READ || ret == MBEDTLS_ERR_SSL_WANT_WRITE || ret == 0 || !found);

  // atlogger_fix_stdout_buffer((char *)recv, *recvlen);
  recv[*recvlen] = '\0'; // null terminate the string

  unsigned char *recvcopy;
  if (atlogger_get_logging_level() >= ATLOGGER_LOGGING_LEVEL_DEBUG) {
    recvcopy = malloc(sizeof(unsigned char) * (*recvlen));
    if (recvcopy != NULL) {
      memcpy(recvcopy, recv, *recvlen);
      atlogger_fix_stdout_buffer((char *)recvcopy, *recvlen);
      atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_DEBUG, "\t%sRECV: %s\"%.*s\"%s\n", BMAG, HMAG, *recvlen, recvcopy,
                   reset);
      free(recvcopy);
    } else {
      atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR,
                   "Failed to allocate memory to pretty print the network received buffer\n");
    }
  }

  if (try_hooks && ctx->hooks->post_recv != NULL) {
    ctx->hooks->_is_nested_call = true;
    ret = ctx->hooks->post_recv(src, srclen, recv, recvsize, recvlen);
    ctx->hooks->_is_nested_call = false;
    if (ret != 0) {
      atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "post_recv hook failed with exit code: %d\n", ret);
      goto exit;
    }
  }

  ret = 0;
  goto exit;
exit: {
  if (allocate_src) {
    free(src);
  }
  return ret;
}
}

int atclient_connection_disconnect(atclient_connection *ctx) {
  int ret = 1;

  if (!ctx->should_be_connected) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR,
                 "ctx->should_be_connected should be true, but is false, it was never connected in the first place!\n");
    goto exit;
  }

  do {
    ret = mbedtls_ssl_close_notify(&(ctx->ssl));
  } while (ret == MBEDTLS_ERR_SSL_WANT_WRITE || ret == MBEDTLS_ERR_SSL_WANT_READ || ret != 0);

  free_contexts(ctx);
  ctx->should_be_connected = false;

  ret = 0;

  goto exit;
exit: { return ret; }
}

bool atclient_connection_is_connected(atclient_connection *ctx) {

  if (!ctx->should_be_connected) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "ctx->should_be_connected should be true, but is false\n");
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
  size_t recvlen;

  int ret = atclient_connection_send(ctx, (unsigned char *)command, commandlen, recv, recvsize, &recvlen);
  if (ret != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "Failed to send \"%s\" to connection: %d\n", command, ret);
    return false;
  }

  if (recvlen <= 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "recvlen is <= 0, connection did not respond to \"%s\"\n", command);
    return false;
  }

  return true;
}

void atclient_connection_free(atclient_connection *ctx) {
  if (ctx->should_be_connected) {
    free_contexts(ctx);
  }
  memset(ctx, 0, sizeof(atclient_connection));
  memset(ctx->host, 0, ATCLIENT_CONSTANTS_HOST_BUFFER_SIZE);
  ctx->port = -1;
  ctx->should_be_connected = false;

  if (ctx->hooks != NULL) {
    free(ctx->hooks);
  }
}

int atclient_connection_get_host_and_port(atclient_atstr *host, int *port, const atclient_atstr url) {
  int ret = 1;

  char *colon = strchr(url.str, ':');
  if (colon == NULL) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "no colon in url\n");
    ret = 1;
    goto exit;
  }

  int hostlen = colon - url.str;
  if (hostlen > ATCLIENT_CONSTANTS_HOST_BUFFER_SIZE) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "hostlen > ATCLIENT_CONSTANTS_HOST_BUFFER_SIZE\n");
    ret = 1;
    goto exit;
  }

  strncpy(host->str, url.str, hostlen);
  host->size = hostlen;
  host->str[hostlen] = '\0';
  *port = atoi(colon + 1);
  if (*port == 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "port is 0\n");
    ret = 1;
    goto exit;
  }

  ret = 0;

  goto exit;

exit: { return ret; }
}

void atclient_connection_enable_hooks(atclient_connection *ctx) {
  ctx->hooks = malloc(sizeof(atclient_connection_hooks));
  memset(ctx->hooks, 0, sizeof(atclient_connection_hooks));
  ctx->hooks->readonly_src = true;
}

// Q. Why is hook a void pointer?
// A. In case we want to add future hook types which use a different function signature
int atclient_connection_hooks_set(atclient_connection *ctx, atclient_connection_hook_type type, void *hook) {
  atclient_connection_hooks *hooks = ctx->hooks;
  if (hooks == NULL) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR,
                 "Make sure to initialize hooks struct before trying to set a hook\n");
    return -1;
  }

  switch (type) {
  case ACHT_NONE:
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "Received 'NONE' hook as hook set input type\n");
    return 1;
  case ACHT_PRE_SEND:
    hooks->pre_send = (atclient_connection_send_hook *)hook;
    break;
  case ACHT_POST_SEND:
    hooks->post_send = (atclient_connection_send_hook *)hook;
    break;
  case ACHT_PRE_RECV:
    hooks->pre_recv = (atclient_connection_send_hook *)hook;
    break;
  case ACHT_POST_RECV:
    hooks->post_recv = (atclient_connection_send_hook *)hook;
    break;
  }

  return 0;
}

void atclient_connection_hooks_set_readonly_src(atclient_connection *ctx, bool readonly_src) {
  if (ctx->hooks == NULL) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR,
                 "Make sure to initialize hooks struct before trying to set readonly_src\n");
    return;
  }
  ctx->hooks->readonly_src = readonly_src;
}
