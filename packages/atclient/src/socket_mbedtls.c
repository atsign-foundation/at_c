// These two headers must be included in a specific order
#include "atchops/platform.h" // IWYU pragma: keep
// Don't move them
#include "atclient/monitor.h"
#include "atclient/socket.h"

#if defined(ATCLIENT_SOCKET_PROVIDER_MBEDTLS)
#include "atchops/constants.h"
#include "atclient/cacerts.h"
#include "atclient/constants.h"
#include "atclient/socket_mbedtls.h"
#include "atlogger/atlogger.h"
#include "mbedtls/error.h"
#include "mbedtls/net_sockets.h"
#include "mbedtls/x509_crt.h"
#include <stdbool.h>
#include <string.h>
#include <unistd.h>
#ifndef PRIu16
#define PRIu16 "hu"
#endif

#define TAG "atclient_socket_mbedtls"

#ifndef SIZE_T_MAX
#define SIZE_T_MAX (size_t) - 1
#endif
// must be less than the maximum for a positive int
// otherwise read_num_bytes may have undefined behavior
#define READ_BLOCK_LEN 4096

// I think the -1 is unnecessary but better safe than sorry
#define MAX_READ_BLOCKS (SIZE_T_MAX / READ_BLOCK_LEN - 1)
static const int MAX_READ_TIMEOUTS = 3;

// Hey fellow engineer, if you want to understand this file, you better have this link on hand:
// https://mbed-tls.readthedocs.io/projects/api/en/v3.6.1/api/file/ssl_8h
// mbedtls sockets are tricky, reading and writing have gotchas
// so you NEED to look at the documentation when you work with them.

static void my_debug(void *ctx, int level, const char *file, int line, const char *str) {
  ((void)level);
  fprintf((FILE *)ctx, "%s:%04d: %s", file, line, str);
  fflush((FILE *)ctx);
}

// Default CA certs for net_sockets
static const char default_ca_pem[] = LETS_ENCRYPT_ROOT GOOGLE_GLOBAL_SIGN GOOGLE_GTS_ROOT_R1 GOOGLE_GTS_ROOT_R2
    GOOGLE_GTS_ROOT_R3 GOOGLE_GTS_ROOT_R4 ZEROSSL_INTERMEDIATE "";

void atclient_raw_socket_init(struct atclient_raw_socket *socket) { mbedtls_net_init(&socket->net); }

void atclient_raw_socket_free(struct atclient_raw_socket *socket) { mbedtls_net_free(&socket->net); }

void atclient_tls_socket_init(struct atclient_tls_socket *socket) {
  memset(socket, 0, sizeof(struct atclient_tls_socket));
  atclient_raw_socket_init(&socket->raw);

  mbedtls_x509_crt_init(&(socket->cacert));
  mbedtls_ctr_drbg_init(&(socket->ctr_drbg));
  mbedtls_entropy_init(&(socket->entropy));
  mbedtls_ssl_config_init(&socket->ssl_config);
  mbedtls_ssl_init(&socket->ssl);
}

void atclient_tls_socket_set_read_timeout(struct atclient_tls_socket *socket, const int timeout_ms) {
  mbedtls_ssl_conf_read_timeout(&socket->ssl_config, timeout_ms);
}

// Expected to be called after init
int atclient_tls_socket_configure(struct atclient_tls_socket *socket, unsigned char *ca_pem, size_t ca_pem_len) {
  int ret = 1;

  // 1. Parse the CA certs
  unsigned char *pem;
  size_t pem_len;
  if (ca_pem == NULL) {
    pem = (unsigned char *)default_ca_pem;
    pem_len = sizeof(default_ca_pem);
  } else {
    pem = ca_pem;
    pem_len = ca_pem_len;
  }

  if ((ret = mbedtls_x509_crt_parse(&(socket->cacert), pem, pem_len)) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "mbedtls_x509_crt_parse failed with exit code: %d\n", ret);
    goto cancel_x509;
  }

  // 2. Seed RNG
  if ((ret = mbedtls_ctr_drbg_seed(&(socket->ctr_drbg), mbedtls_entropy_func, &(socket->entropy),
                                   (unsigned char *)ATCHOPS_RNG_PERSONALIZATION,
                                   strlen(ATCHOPS_RNG_PERSONALIZATION))) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "mbedtls_ctr_drbg_seed failed with exit code: %d\n", ret);
    goto cancel_seed;
  }

  // 3. Configure SSL
  if ((ret = mbedtls_ssl_config_defaults(&(socket->ssl_config), MBEDTLS_SSL_IS_CLIENT, MBEDTLS_SSL_TRANSPORT_STREAM,
                                         MBEDTLS_SSL_PRESET_DEFAULT)) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "mbedtls_ssl_config_defaults failed with exit code: %d\n", ret);
    goto cancel_ssl_config;
  }

  mbedtls_ssl_conf_ca_chain(&(socket->ssl_config), &(socket->cacert), NULL);
  mbedtls_ssl_conf_authmode(&(socket->ssl_config), MBEDTLS_SSL_VERIFY_REQUIRED);
  mbedtls_ssl_conf_rng(&(socket->ssl_config), mbedtls_ctr_drbg_random, &(socket->ctr_drbg));
  mbedtls_ssl_conf_dbg(&(socket->ssl_config), my_debug, stdout);
  mbedtls_ssl_conf_read_timeout(&(socket->ssl_config),
                                ATCLIENT_CLIENT_READ_TIMEOUT_MS); // recv will timeout after X seconds

  // 4. Prepare the SSL context
  if ((ret = mbedtls_ssl_setup(&(socket->ssl), &(socket->ssl_config))) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "mbedtls_ssl_setup failed with exit code: %d\n", ret);
    goto cancel_ssl;
  }

  // we made it to the happy path: skip freeing all the things
  ret = 0;
  goto exit;
cancel_ssl:
  mbedtls_ssl_free(&socket->ssl);
cancel_ssl_config:
  mbedtls_ssl_config_free(&socket->ssl_config);
cancel_seed:
  mbedtls_entropy_free(&(socket->entropy));
  mbedtls_ctr_drbg_free(&(socket->ctr_drbg));
cancel_x509:
  mbedtls_x509_crt_free(&(socket->cacert));
exit:
  return ret;
}

void atclient_tls_socket_free(struct atclient_tls_socket *socket) {
  if (socket != NULL) {
    atclient_raw_socket_free(&socket->raw);
    mbedtls_ssl_free(&socket->ssl);
    mbedtls_ssl_config_free(&socket->ssl_config);
    mbedtls_entropy_free(&(socket->entropy));
    mbedtls_ctr_drbg_free(&(socket->ctr_drbg));
    mbedtls_x509_crt_free(&(socket->cacert));
    memset(socket, 0, sizeof(struct atclient_tls_socket));
  }
}

static int atclient_tls_socket_ssl_handshake(struct atclient_tls_socket *socket, const char *host);

int atclient_tls_socket_connect(struct atclient_tls_socket *socket, const char *host, const uint16_t port) {
  if (socket == NULL) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "tls socket is when trying to connect NULL\n");
    return 1;
  }

  char port_str[5];
  snprintf(port_str, 5, "%" PRIu16, port);

  int ret;
  // 1. Connect
  // TODO: move to raw_connect function
  if ((ret = mbedtls_net_connect(&socket->raw.net, host, port_str, MBEDTLS_NET_PROTO_TCP)) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "mbedtls_net_connect failed with exit code: %d\n", ret);
    return ret;
  }

  if ((ret = atclient_tls_socket_ssl_handshake(socket, host)) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atclient_tls_socket_ssl_handshake failed with exit code: %d\n",
                 ret);
    return ret;
  }

  return ret;
}

static int atclient_tls_socket_ssl_handshake(struct atclient_tls_socket *socket, const char *host) {
  int ret;
  // 2. Set SSL hostname
  if ((ret = mbedtls_ssl_set_hostname(&socket->ssl, host)) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "mbedtls_ssl_set_hostname failed with exit code: %d\n", ret);
    return ret;
  }

  // 3. Link SSL to the raw socket
  mbedtls_ssl_set_bio(&socket->ssl, &socket->raw.net, mbedtls_net_send, NULL, mbedtls_net_recv_timeout);

  /*
   * 4. Do SSL handshake
   */
  if ((ret = mbedtls_ssl_handshake(&socket->ssl)) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "mbedtls_ssl_handshake failed with exit code: %d\n", ret);
    return ret;
  }

  /*
   * 5. Verify the certificate
   */
  if ((ret = mbedtls_ssl_get_verify_result(&socket->ssl)) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "mbedtls_ssl_get_verify_result failed with exit code: %d\n", ret);
    return ret;
  }

  return ret;
}

int atclient_tls_socket_disconnect(struct atclient_tls_socket *socket) {
  if (socket == NULL) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atclient_tls_socket_disconnect: socket is NULL\n");
    return 1;
  }

  int ret = mbedtls_ssl_close_notify(&(socket->ssl));

  // If we got a non want read/write error don't try again:
  // we may segfault or deadlock trying to disconnect
  // just warn that we silently closed the socket and move on
  if (ret != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_WARN,
                 "mbedtls_ssl_close_notify failed, socket will be silently closed, exit code: %d\n", ret);
    return ret;
  }

  return ret;
}

static bool should_continue_write(size_t pos, size_t len, int ret) {
  return pos < len || ret == MBEDTLS_ERR_SSL_WANT_READ || ret == MBEDTLS_ERR_SSL_WANT_WRITE ||
         ret == MBEDTLS_ERR_SSL_ASYNC_IN_PROGRESS || ret == MBEDTLS_ERR_SSL_CRYPTO_IN_PROGRESS;
}
int atclient_tls_socket_write(struct atclient_tls_socket *socket, const unsigned char *value, size_t value_len) {
  if (socket == NULL) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atclient_tls_socket_write: socket is NULL\n");
    return 1;
  }
  if (value == NULL) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atclient_tls_socket_write: value is NULL\n");
    return 2;
  }
  size_t pos = 0;
  int ret;
  do {
    ret = mbedtls_ssl_write(&socket->ssl, value + pos, value_len - pos);
    if (ret > 0) {
      pos += (size_t)ret;
      ret = 0;
      continue;
    }
  } while (should_continue_write(pos, value_len, ret));
  if (ret != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "mbedtls_ssl_write failed with exit code: %d\n", ret);
  }
  return ret;
}

static int atclient_tls_socket_read_until_char(struct atclient_tls_socket *socket, unsigned char **value,
                                               size_t *value_len, char until_char);

// static int atclient_tls_socket_read_num_bytes(struct atclient_tls_socket *socket, unsigned char **value,
//                                               size_t *value_len, size_t num_bytes);
int atclient_tls_socket_read(struct atclient_tls_socket *socket, unsigned char **value, size_t *value_len,
                             const struct atclient_socket_read_options options) {
  if (socket == NULL) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atclient_tls_socket_read: socket is NULL\n");
    return 1;
  }

  switch (options.type) {

  // case ATCLIENT_SOCKET_READ_NUM_BYTES:
  // return atclient_tls_socket_read_num_bytes(socket, value, value_len, options.num_bytes);
  case ATCLIENT_SOCKET_READ_UNTIL_CHAR:
    return atclient_tls_socket_read_until_char(socket, value, value_len, options.until_char);
  default:
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atclient_tls_socket_read: read type %d is not a valid type\n",
                 options.type);
    return 4;
  }
}

int atclient_tls_socket_read_until_char(struct atclient_tls_socket *socket, unsigned char **value, size_t *value_len,
                                        char until_char) {
  // Assume params have been validated by socket_read
  int ret;
  unsigned char *recv = NULL;
  size_t blocks = 0; // number of allocated blocks

  do {
    size_t offset = READ_BLOCK_LEN * blocks; // offset to current block
    // Allocate memory
    unsigned char *temp = realloc(recv, sizeof(unsigned char) * (offset + READ_BLOCK_LEN));
    if (temp == NULL) {
      atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "Failed to allocate receive buffer\n");
      if (recv != NULL) {
        free(recv);
      }
      return 1;
    }
    recv = temp; // once we ensure realloc was successful we set recv to the new memory

    // Read into current block
    size_t pos = 0; // position in current block
    do {
      // When reading to a character we must read byte by byte to prevent
      // over reading and risk corrupting the next message
      // do not change the 1 without consulting the code below
      ret = mbedtls_ssl_read(&socket->ssl, recv + offset + pos, 1);
      if (ret > 0) {
        if (until_char == *(recv + offset + pos)) { // check if this is the char we need
          if (value != NULL) {
            *value = recv;
          } else {
            free(recv);
          }
          if (value_len != NULL) {
            *value_len = offset + pos + 1;
          }
          // The only return where recv should not be freed
          return 0;
        }
        pos += ret; // successful read, increment position
        continue;   // continue if not found char yet
      }
      // handle non-happy path
      atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_DEBUG, "Socket read error: %d\n", ret);
      switch (ret) {
      case 0:                                 // connection is closed
      case MBEDTLS_ERR_SSL_PEER_CLOSE_NOTIFY: // connection is closed
        atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "Socket closed while reading: %d\n", ret);
        ret = MBEDTLS_ERR_SSL_PEER_CLOSE_NOTIFY; // ensure ret val is not 0
        free(recv);
        return ret;
      case MBEDTLS_ERR_SSL_WANT_READ:          // handshake incomplete
      case MBEDTLS_ERR_SSL_WANT_WRITE:         // handshake incomplete
      case MBEDTLS_ERR_SSL_ASYNC_IN_PROGRESS:  // async operation in progress
      case MBEDTLS_ERR_SSL_CRYPTO_IN_PROGRESS: // crypto operation in progress
                                               // async error, we need to try again
        break;
      case MBEDTLS_ERR_SSL_TIMEOUT:
        return ATCLIENT_SSL_TIMEOUT_EXITCODE;
        break;
        // unexpected errors while reading
      default:
        if (ret > 0) {
          atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "Unexpected read value %d\n", ret);
        } else {
          char strerr[512];
          mbedtls_strerror(ret, strerr, 512);
          atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "%s\n", strerr);
        }
        free(recv);
        return ret;
      } // don't put anything after switch without checking it first
    } while (pos < READ_BLOCK_LEN);
    blocks++;
  } while (blocks < MAX_READ_BLOCKS);
  // We should only arrive at this point if we max out blocks
  // Every other code path should return early
  atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "Failed to read within the maximum allowed number of read blocks\n");
  free(recv);
  return 1;
}
#endif
