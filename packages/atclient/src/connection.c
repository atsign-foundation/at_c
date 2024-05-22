
#include "atclient/connection.h"
#include "atclient/stringutils.h"
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

void atclient_connection_init(atclient_connection *ctx) {

  if (ctx == NULL) {
    return; // how should we handle this error?
  }

  memset(ctx, 0, sizeof(atclient_connection));
  memset(ctx->host, 0, ATCLIENT_CONSTANTS_HOST_BUFFER_SIZE);
  ctx->port = -1;
  ctx->should_be_connected = false;
}

int atclient_connection_connect(atclient_connection *ctx, const char *host, const int port) {
  int ret = 1;

  init_contexts(ctx);
  ctx->should_be_connected = true;

  atclient_atstr readbuf;
  atclient_atstr_init(&readbuf, 1024);

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
  mbedtls_ssl_conf_read_timeout(&(ctx->ssl_config), ATCLIENT_CONSTANTS_READ_TIMEOUT); // recv will timeout after X seconds

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
  ret = mbedtls_ssl_read(&(ctx->ssl), (unsigned char *)readbuf.str, readbuf.size);
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
  ret = mbedtls_ssl_read(&(ctx->ssl), (unsigned char *)readbuf.str, readbuf.size);
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
  atclient_atstr_free(&readbuf);
  if (ret != 0) {
    // undo what we set
    memset(ctx->host, 0, ATCLIENT_CONSTANTS_HOST_BUFFER_SIZE);
    ctx->port = -1;
  }
  return ret;
}
}

int atclient_connection_send(atclient_connection *ctx, const unsigned char *src, const size_t srclen,
                             unsigned char *recv, const size_t recvsize, size_t *recvlen) {
  int ret = 1;

  if(!ctx->should_be_connected)
  {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "ctx->should_be_connected should be true, but is false\n");
    goto exit;
  }

  ret = mbedtls_ssl_write(&(ctx->ssl), src, srclen);
  if (ret <= 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "mbedtls_ssl_write failed with exit code: %d\n", ret);
    goto exit;
  }

  if (atlogger_get_logging_level() >= ATLOGGER_LOGGING_LEVEL_DEBUG) {
    unsigned char srccopy[srclen];
    memcpy(srccopy, src, srclen);
    atlogger_fix_stdout_buffer((char *) srccopy, srclen);
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_INFO, "\t%sSENT: %s\"%.*s\"%s\n", BBLU, HCYN, strlen((char *) srccopy), srccopy,
                 reset);
  }

  if (recv == NULL) {
    ret = 0;
    goto exit;
  }

  bool found = false;
  size_t l = 0;
  do {
    ret = mbedtls_ssl_read(&(ctx->ssl), recv + l, recvsize - l);
    if (ret < 0) {
      goto exit;
    }
    l = l + ret;

    for (int i = l; i >= l - ret && i >= 0; i--) {
      // printf("i: %d c: %.2x\n", i, (unsigned char) *(recv + i));
      if (*(recv + i) == '\n') {
        *recvlen = i;
        found = true;
        break;
      }
    }
    if (found) {
      break;
    }

  } while (ret == MBEDTLS_ERR_SSL_WANT_READ || !found);

  if (ret <= 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "mbedtls_ssl_read failed with exit code: %d\n", ret);
    goto exit;
  }

  recv[*recvlen] = '\0'; // null terminate the string


  if(atlogger_get_logging_level() >= ATLOGGER_LOGGING_LEVEL_DEBUG) {
    unsigned char recvcopy[*recvlen];
    memcpy(recvcopy, recv, *recvlen);
    atlogger_fix_stdout_buffer((char *) recvcopy, *recvlen);
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_DEBUG, "\t%sRECV: %s\"%.*s\"%s\n", BMAG, HMAG, strlen(recvcopy), recvcopy, reset);
  }

  ret = 0;
  goto exit;
exit: { return ret; }
}

int atclient_connection_disconnect(atclient_connection *ctx) {
  int ret = 1;

  if(!ctx->should_be_connected) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "ctx->should_be_connected should be true, but is false, it was never connected in the first place!\n");
    goto exit;
  }

  do {
    ret = mbedtls_ssl_close_notify(&(ctx->ssl));
  } while (ret == MBEDTLS_ERR_SSL_WANT_WRITE || ret == MBEDTLS_ERR_SSL_WANT_READ || ret != 0);

  free_contexts(ctx);
  ctx->should_be_connected = false;

  ret = 0;

  goto exit;
exit: {
  return ret;
}
}

int atclient_connection_is_connected(atclient_connection *ctx) {
  int ret = -1;

  if(!ctx->should_be_connected) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "ctx->should_be_connected should be true, but is false\n");
    return ret;
  }

  const char *command = "\n";
  const size_t commandlen = strlen(command);

  const size_t recvsize = 64;
  unsigned char recv[recvsize];
  memset(recv, 0, sizeof(unsigned char) * recvsize);
  size_t recvlen;

  ret = atclient_connection_send(ctx, (unsigned char *)command, commandlen, recv,
                                 recvsize, &recvlen);
  if (ret != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "Failed to send \'\\n\' to connection: %d\n", ret);
    ret = -1;
    goto exit;
  }

  if(recvlen <= 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "recvlen is <= 0, connection did not respond to \'\\n\'\n");
    ret = 0;
    goto exit;
  }

  ret = 1;
  goto exit;

exit: { return ret; }
}

void atclient_connection_free(atclient_connection *ctx) {
  if(ctx->should_be_connected) {
    free_contexts(ctx);
  }
  memset(ctx, 0, sizeof(atclient_connection));
  memset(ctx->host, 0, ATCLIENT_CONSTANTS_HOST_BUFFER_SIZE);
  ctx->port = -1;
  ctx->should_be_connected = false;
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
