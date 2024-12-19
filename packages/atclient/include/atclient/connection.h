/*
 *
 * The connection family of types and methods represents a single connection to
 * if you want a pure socket representation see socket.h.
 *
 * At the moment _socket represents a singular tcp socket, but in the future it may be altered
 * to be a union of different connection types, such as a websocket or other construct.
 * It is considered an internal construct and is subject to breaking changes across
 * minor releases, especially while at_c remains in beta status.
 *
 */
#ifndef ATCLIENT_CONNECTION_H
#define ATCLIENT_CONNECTION_H
#ifdef __cplusplus
extern "C" {
#endif

#include <atchops/platform.h> // IWYU pragma: keep

#include "atclient/connection_hooks.h"
#include "atclient/socket.h"
#include <stdbool.h>
#include <stddef.h>

// represents the type of connection
typedef enum atclient_connection_type {
  ATCLIENT_CONNECTION_TYPE_ATDIRECTORY, // uses '\n' to check if it is connected
  ATCLIENT_CONNECTION_TYPE_ATSERVER     // uses 'noop:0\r\n' to check if it is connected
} atclient_connection_type;

typedef struct atclient_connection {
  atclient_connection_type type; // set in atclient_connection_init
  uint16_t port;                 // example: 64
  bool _is_host_initialized : 1;
  bool _is_port_initialized : 1;
  bool _is_connection_enabled : 1;
  bool _is_hooks_enabled : 1;

  char *host; // example: "root.atsign.org"

  // atclient_connection_connect sets this to true and atclient_connection_disconnect sets this to false
  // this does not mean that the connection is still alive, it just means that the connection was established at least
  // once, at some  point, check atclient_connection_is_connected for a live status on the connection
  // _is_connection_enabled also serves as an internal boolean to check if the following mbedlts contexts have been
  // initialized and need to be freed at the end

  struct atclient_tls_socket _socket;
  atclient_connection_hooks *hooks;
} atclient_connection;

/**
 * @brief initialize the context for a connection. this function should be called before use of any other function
 *
 * @param ctx the context to initialize
 * @param type the type of connection to initialize,
 * if it is ATCLIENT_CONNECTION_TYPE_ROOT, then '\\n' will be used to check if it is connected.
 * if it is ATCLIENT_CONNECTION_TYPE_ATSERVER, then 'noop:0\r\n' will be used to check if it is connected
 */
void atclient_connection_init(atclient_connection *ctx, atclient_connection_type type);

/**
 * @brief free memory allocated by the init function
 *
 * @param ctx the struct which was previously initialized
 */
void atclient_connection_free(atclient_connection *ctx);

/**
 * @brief after initializing a connection context, connect to a host and port
 *
 * @param ctx the initialized context
 * @param host the host to connect to
 * @param port the port to connect to
 * @return int 0 on success, otherwise error
 */
int atclient_connection_connect(atclient_connection *ctx, const char *host, const uint16_t port);

/**
 * @brief Reads data from the connection
 *
 * @param ctx the connection initialized and connected using atclient_connection_init and atclient_connection_connect
 * @param value a double pointer that will be allocated by the function to the data read, assumed to be non-null and a
 * null pointer
 * @param value_len the length of the data read, will be set by the function, setting this to NULL will skip setting the
 * length
 * @param value_max_len the maximum length of the data to read, setting this to 0 means no limit
 * @return int 0 on success
 */
int atclient_connection_read(atclient_connection *ctx, unsigned char **value, size_t *value_len);

/**
 * @brief Write data to the connection
 *
 * @param ctx connection initialized and connected using atclient_connection_init and atclient_connection_connect
 * @param value the data to write
 * @param value_len the length of the data to write
 * @return int 0 on success
 */
int atclient_connection_write(atclient_connection *ctx, const unsigned char *value, const size_t value_len);

/**
 * @brief send data to the connection
 *
 * @param ctx the connection which was initialized (via the init function) and connected (via the connect function)
 * @param src the data to send
 * @param src_len the length of the data to send
 * @param recv the buffer to receive data
 * @param recv_size the length of the buffer to receive data
 * @param recv_len the length of the data received (output)
 * @return int 0 on success, otherwise error
 *
 * @note if recv is NULL, then this function will skip reading the response
 */
int atclient_connection_send(atclient_connection *ctx, const unsigned char *src, const size_t src_len,
                             unsigned char *recv, const size_t recv_size, size_t *recv_len);

/**
 * @brief disconnect a connection
 *
 * @param ctx the connection to disconnect
 * @return int 0 on success, otherwise error
 */
int atclient_connection_disconnect(atclient_connection *ctx);

/**
 * @brief checks if the connection is connected
 *
 * @param ctx the connection to check
 * @return true if the connection is connected, otherwise false if it is not connected or an error occurred
 */
bool atclient_connection_is_connected(atclient_connection *ctx);

/**
 * @brief set the blocking read timeout of the connection
 * 
 * @param ctx the connection to set the read timeout on, assumed to be initialized and connected
 * @param timeout_ms the timeout in milliseconds
 * @return void
 */
void atclient_connection_set_read_timeout(atclient_connection *ctx, const uint32_t timeout_ms);

#ifdef __cplusplus
}
#endif
#endif
