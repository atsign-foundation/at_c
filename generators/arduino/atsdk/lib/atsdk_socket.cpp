#include "./atsdk_socket.h"
#include "./atsdk.h"
#include <cstring>

#ifndef __clang__
#include <Arduino.h>
#include <ArduinoBearSSL.h>
#include <ArduinoECCX08.h>
#include <WiFi.h>
#else
#include <atclient/atclient.h>
#endif

extern "C" {

#ifndef SIZE_T_MAX
#define SIZE_T_MAX (size_t) - 1
#endif
// must be less than the maximum for a positive int
// otherwise read_num_bytes may have undefined behavior
#define READ_BLOCK_LEN 4096

// I think the -1 is unnecessary but better safe than sorry
#define MAX_READ_BLOCKS (SIZE_T_MAX / READ_BLOCK_LEN - 1)
static const int MAX_READ_TIMEOUTS = 1000;

#define TAG "atsdk_wifi_tls_socket"
// Converts opaque pointer socket->wificlient back to a WifiClient*

// Let the socket lifetime be managed externally
void atclient_raw_socket_init(struct atclient_raw_socket *) {}
void atclient_raw_socket_free(struct atclient_raw_socket *) {}
void atclient_tls_socket_set_read_timeout(struct atclient_tls_socket *, const int) {}
void atclient_tls_socket_init(struct atclient_tls_socket *) {}
void atclient_tls_socket_free(struct atclient_tls_socket *) {}

void atclient_setup_bearssl(atclient *atclient, BearSSLClient *ssl_client) {
  atclient->atserver_connection._socket.bear_ssl_client = (void *)ssl_client;
}

int atclient_tls_socket_configure(struct atclient_tls_socket *, unsigned char *, size_t) { return 0; }

int atclient_tls_socket_connect(struct atclient_tls_socket *socket, const char *host, const uint16_t port) {
  return socket->bear_ssl_client->connect(host, port) == 0;
}

int atclient_tls_socket_disconnect(struct atclient_tls_socket *socket) {
  socket->bear_ssl_client->stop();
  return 0;
}

int atclient_tls_socket_write(struct atclient_tls_socket *socket, const unsigned char *value, size_t value_len) {
  size_t ret = socket->bear_ssl_client->write(value, value_len);
  return ret = value_len;
}

int atclient_tls_socket_read(struct atclient_tls_socket *socket, unsigned char **value, size_t *value_len,
                             const struct atclient_socket_read_options options) {
  if (options.type != ATCLIENT_SOCKET_READ_UNTIL_CHAR) {
    // Nothing else implemented right now
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "read options type %d is not a valid type\n", options.type);
    return 1;
  }
  char until_char = options.until_char;
  int c;

  unsigned char *recv = NULL;
  size_t blocks = 0; // number of allocated blocks

  do {
    size_t offset = READ_BLOCK_LEN * blocks; // offset to current block
    // Allocate memory
    unsigned char *temp = (unsigned char *)realloc(recv, sizeof(unsigned char) * (offset + READ_BLOCK_LEN));
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
    int timeout_count = 0;
    do {
      // When reading to a character we must read byte by byte to prevent
      // over reading and risk corrupting the next message
      if (!socket->bear_ssl_client->available()) {
        timeout_count++;
        if (timeout_count == MAX_READ_TIMEOUTS) {
          atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "Failed to read the full message after %d attempts\n",
                       MAX_READ_TIMEOUTS);
          free(recv);
          return 1;
        }
        delay(1);
        continue;
      }
      c = socket->bear_ssl_client->read();
      Serial.print(c);
      recv[offset + pos] = c;
      pos++;
      if (until_char == c) {
        *value = recv;
        *value_len = offset + pos;
        return 0;
      }
      // handle non-happy path
    } while (pos < READ_BLOCK_LEN);
    blocks++;
  } while (blocks < MAX_READ_BLOCKS);
  // We should only arrive at this point if we max out blocks
  // Every other code path should return early
  atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "Failed to read within the maximum allowed number of read blocks\n");
  free(recv);
  return 1;
}
}
