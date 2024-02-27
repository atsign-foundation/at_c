
#include "atclient/connection.h"
#include "atchops/constants.h"
#include "atclient/atstr.h"
#include "atclient/cacerts.h"
#include "atlogger/atlogger.h"
#include <mbedtls/ctr_drbg.h>
#include <mbedtls/entropy.h>
#include <mbedtls/net_sockets.h>
#include <mbedtls/ssl.h>
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

void atclient_connection_init(atclient_connection *ctx) {
  memset(ctx, 0, sizeof(atclient_connection));
  memset(ctx->host, 0, ATCLIENT_CONSTANTS_HOST_BUFFER_SIZE);
  ctx->port = -1;

  mbedtls_net_init(&(ctx->net));
  mbedtls_ssl_init(&(ctx->ssl));
  mbedtls_ssl_config_init(&(ctx->ssl_config));
  mbedtls_x509_crt_init(&(ctx->cacert));
  mbedtls_entropy_init(&(ctx->entropy));
  mbedtls_ctr_drbg_init(&(ctx->ctr_drbg));
}

int atclient_connection_connect(atclient_connection *ctx, const char *host, const int port) {
  int ret = 1;

  atclient_atstr readbuf;
  atclient_atstr_init(&readbuf, 1024);

  strcpy(ctx->host, host); // assume null terminated, example: "root.atsign.org"
  ctx->port = port;        // example: 64

  char portstr[6];
  sprintf(portstr, "%d", ctx->port);

  ret = mbedtls_ctr_drbg_seed(&(ctx->ctr_drbg), mbedtls_entropy_func, &(ctx->entropy), ATCHOPS_RNG_PERSONALIZATION,
                              strlen(ATCHOPS_RNG_PERSONALIZATION));
  if (ret != 0) {
    atclient_atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "mbedtls_ctr_drbg_seed failed with exit code: %d\n", ret);
    goto exit;
  }

  ret = mbedtls_x509_crt_parse(&(ctx->cacert), (unsigned char *)cas_pem, cas_pem_len);
  if (ret != 0) {
    atclient_atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "mbedtls_x509_crt_parse failed with exit code: %d\n", ret);
    goto exit;
  }

  ret = mbedtls_net_connect(&(ctx->net), host, portstr, MBEDTLS_NET_PROTO_TCP);
  if (ret != 0) {
    atclient_atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "mbedtls_net_connect failed with exit code: %d\n", ret);
    goto exit;
  }

  ret = mbedtls_ssl_config_defaults(&(ctx->ssl_config), MBEDTLS_SSL_IS_CLIENT, MBEDTLS_SSL_TRANSPORT_STREAM,
                                    MBEDTLS_SSL_PRESET_DEFAULT);
  if (ret != 0) {
    atclient_atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "mbedtls_ssl_config_defaults failed with exit code: %d\n",
                          ret);
    goto exit;
  }

  mbedtls_ssl_conf_ca_chain(&(ctx->ssl_config), &(ctx->cacert), NULL);
  mbedtls_ssl_conf_authmode(&(ctx->ssl_config), MBEDTLS_SSL_VERIFY_REQUIRED);
  mbedtls_ssl_conf_rng(&(ctx->ssl_config), mbedtls_ctr_drbg_random, &(ctx->ctr_drbg));
  mbedtls_ssl_conf_dbg(&(ctx->ssl_config), my_debug, stdout);

  ret = mbedtls_ssl_setup(&(ctx->ssl), &(ctx->ssl_config));
  if (ret != 0) {
    atclient_atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "mbedtls_ssl_setup failed with exit code: %d\n", ret);
    goto exit;
  }

  ret = mbedtls_ssl_set_hostname(&(ctx->ssl), host);
  if (ret != 0) {
    atclient_atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "mbedtls_ssl_set_hostname failed with exit code: %d\n",
                          ret);
    goto exit;
  }

  mbedtls_ssl_set_bio(&(ctx->ssl), &(ctx->net), mbedtls_net_send, mbedtls_net_recv, mbedtls_net_recv_timeout);

  ret = mbedtls_ssl_handshake(&(ctx->ssl));
  if (ret != 0) {
    atclient_atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "mbedtls_ssl_handshake failed with exit code: %d\n", ret);
    goto exit;
  }

  ret = mbedtls_ssl_get_verify_result(&(ctx->ssl));
  if (ret != 0) {
    atclient_atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR,
                          "mbedtls_ssl_get_verify_result failed with exit code: %d\n", ret);
    goto exit;
  }

  // ===============
  // after connect
  // ===============

  // read anything that was already sent
  ret = mbedtls_ssl_read(&(ctx->ssl), (unsigned char *)readbuf.str, readbuf.len);
  if (ret < 0) {
    atclient_atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "mbedtls_ssl_read failed with exit code: %d\n", ret);
    goto exit;
  }

  // press enter
  ret = mbedtls_ssl_write(&(ctx->ssl), (const unsigned char *)"\r\n", 2);
  if (ret < 0) {
    atclient_atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "mbedtls_ssl_write failed with exit code: %d\n", ret);
    goto exit;
  }

  // read anything that was sent
  ret = mbedtls_ssl_read(&(ctx->ssl), (unsigned char *)readbuf.str, readbuf.len);
  if (ret < 0) {
    atclient_atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "mbedtls_ssl_read failed with exit code: %d\n", ret);
    goto exit;
  }

  // now we are guaranteed a blank canvas
  if (ret > 0) {
    ret = 0; // a positive exit code is not an error
  }

  goto exit;

exit: {
  atclient_atstr_free(&readbuf);
  return ret;
}
}

static void fix_stdout_buffer(char *str, const unsigned long strlen) {
  // if str == 'Jeremy\r\n', i want it to be 'Jeremy'
  // if str == 'Jeremy\n', i want it to be 'Jeremy'
  // if str == 'Jeremy\r', i want it to be 'Jeremy'

  if (strlen == 0) {
    goto exit;
  }

  int carriagereturnindex = -1;
  int newlineindex = -1;

  for (int i = strlen; i >= 0; i--) {
    if (str[i] == '\r' && carriagereturnindex == -1) {
      carriagereturnindex = i;
    }
    if (carriagereturnindex != -1 && newlineindex != -1) {
      break;
    }
  }

  if (carriagereturnindex != -1) {
    for (int i = carriagereturnindex; i < strlen - 1; i++) {
      str[i] = str[i + 1];
    }
    str[strlen - 1] = '\0';
  }

  for (int i = strlen; i >= 0; i--) {
    if (str[i] == '\n' && newlineindex == -1) {
      newlineindex = i;
    }
    if (carriagereturnindex != -1 && newlineindex != -1) {
      break;
    }
  }

  if (newlineindex != -1) {
    for (int i = newlineindex; i < strlen - 1; i++) {
      str[i] = str[i + 1];
    }
    str[strlen - 1] = '\0';
  }

  goto exit;

exit: { return; }
}

int atclient_connection_send(atclient_connection *ctx, const unsigned char *src, const unsigned long srclen,
                             unsigned char *recv, const unsigned long recvlen, unsigned long *olen) {
  int ret = 1;

  atclient_atstr stdoutbuffer;
  atclient_atstr_init(&stdoutbuffer, 32768);

  ret = mbedtls_ssl_write(&(ctx->ssl), src, srclen);
  if (ret < 0) {
    goto exit;
  }

  ret = atclient_atstr_set_literal(&stdoutbuffer, "%.*s", (int)srclen, src);
  if (ret != 0) {
    atclient_atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atclient_atstr_set_literal failed\n");
    goto exit;
  }

  fix_stdout_buffer(stdoutbuffer.str, stdoutbuffer.olen);

  atclient_atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_INFO, "\t%sSENT: %s\"%.*s\"\e[0m\n", "\e[1;34m", "\e[0;96m",
                        (int)stdoutbuffer.olen, stdoutbuffer.str);

  memset(recv, 0, recvlen);
  int found = 0;
  unsigned long l = 0;
  do {
    ret = mbedtls_ssl_read(&(ctx->ssl), recv + l, recvlen - l);
    if (ret < 0) {
      goto exit;
    }
    l = l + ret;

    for (int i = l; i >= l - ret && i >= 0; i--) {
      // printf("i: %d c: %.2x\n", i, (unsigned char) *(recv + i));
      if (*(recv + i) == '\n') {
        *olen = i;
        found = 1;
        break;
      }
    }
    if (found == 1) {
      break;
    }

  } while (ret == MBEDTLS_ERR_SSL_WANT_READ || found == 0);

  if (ret < 0) {
    goto exit;
  }

  atclient_atstr_reset(&stdoutbuffer);
  ret = atclient_atstr_set_literal(&stdoutbuffer, "%.*s", (int)*olen, recv);
  if (ret != 0) {
    atclient_atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atclient_atstr_set_literal failed\n");
    goto exit;
  }
  fix_stdout_buffer(stdoutbuffer.str, stdoutbuffer.olen);

  atclient_atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_INFO, "\t%sRECV: %s\"%.*s\"\e[0m\n", "\e[1;35m", "\e[0;95m",
                        (int)stdoutbuffer.olen, stdoutbuffer.str);
  memset(recv, 0, sizeof(unsigned char) * recvlen); // clear the buffer
  memcpy(recv, stdoutbuffer.str, stdoutbuffer.olen);
  goto exit;

exit: {
  atclient_atstr_free(&stdoutbuffer);
  return ret;
}
}

int atclient_connection_disconnect(atclient_connection *ctx) {
  int ret = 0;
  do {
    ret = mbedtls_ssl_close_notify(&(ctx->ssl));
  } while (ret == MBEDTLS_ERR_SSL_WANT_WRITE);
  ret = 0;

  atclient_connection_free(ctx);
  return ret;
}

int atclient_connection_is_connected(atclient_connection *ctx) {
  int ret = 0; // false by default
  const char *cmd = "\r\n";
  const unsigned long cmdlen = strlen(cmd);
  const unsigned long recvlen = 128;
  unsigned char *recv = malloc(sizeof(unsigned char) * recvlen);
  memset(recv, 0, recvlen);
  unsigned long olen = 0;

  ret = atclient_connection_send(ctx, (const unsigned char *)cmd, cmdlen, recv, recvlen, &olen);
  if (ret != 0) {
    goto exit;
  }

  if (olen > 0) {
    ret = 1; // true
  } else {
    ret = 0; // false
  }

  goto exit;

exit: {
  free(recv);
  return ret;
}
}

void atclient_connection_free(atclient_connection *ctx) {
  mbedtls_net_free(&(ctx->net));
  mbedtls_ssl_free(&(ctx->ssl));
  mbedtls_ssl_config_free(&(ctx->ssl_config));
  mbedtls_x509_crt_free(&(ctx->cacert));
  mbedtls_entropy_free(&(ctx->entropy));
  mbedtls_ctr_drbg_free(&(ctx->ctr_drbg));
}

int atclient_connection_get_host_and_port(atclient_atstr *host, int *port, const atclient_atstr url) {
  int ret = 1;

  char *colon = strchr(url.str, ':');
  if (colon == NULL) {
    atclient_atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "no colon in url\n");
    ret = 1;
    goto exit;
  }

  int hostlen = colon - url.str;
  if (hostlen > ATCLIENT_CONSTANTS_HOST_BUFFER_SIZE) {
    atclient_atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "hostlen > ATCLIENT_CONSTANTS_HOST_BUFFER_SIZE\n");
    ret = 1;
    goto exit;
  }

  strncpy(host->str, url.str, hostlen);
  host->len = hostlen;
  host->str[hostlen] = '\0';
  *port = atoi(colon + 1);
  if (*port == 0) {
    atclient_atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "port is 0\n");
    ret = 1;
    goto exit;
  }

  ret = 0;

  goto exit;

exit: { return ret; }
}
