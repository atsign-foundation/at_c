#ifndef ATCLIENT_CONNECTION_H
#define ATCLIENT_CONNECTION_H

#include <mbedtls/ctr_drbg.h>
#include <mbedtls/entropy.h>
#include <mbedtls/net_sockets.h>
#include <mbedtls/ssl.h>
#include <stdbool.h>
#include <stddef.h>

#define ATCLIENT_CONSTANTS_HOST_BUFFER_SIZE 128 // the size of the buffer for the host name

// represents the type of connection
typedef enum atclient_connection_type {
  ATCLIENT_CONNECTION_TYPE_ATDIRECTORY, // uses '\n' to check if it is connected
  ATCLIENT_CONNECTION_TYPE_ATSERVER     // uses 'noop:0\r\n' to check if it is connected
} atclient_connection_type;

typedef int(atclient_connection_send_hook)(const unsigned char *src, const size_t src_len, unsigned char *recv,
                                           const size_t recv_size, size_t *recv_len);

typedef enum atclient_connection_hook_type {
  ATCLIENT_CONNECTION_HOOK_TYPE_NONE = 0,
  ATCLIENT_CONNECTION_HOOK_TYPE_PRE_SEND,
  ATCLIENT_CONNECTION_HOOK_TYPE_POST_SEND,
  ATCLIENT_CONNECTION_HOOK_TYPE_PRE_RECV,
  ATCLIENT_CONNECTION_HOOK_TYPE_POST_RECV,
} atclient_connection_hook_type;

typedef struct atclient_connection_hooks {
  bool _is_nested_call; // internal variable for preventing infinite recursion (hooks cannot trigger other hooks in
                        // their nested calls)
  atclient_connection_send_hook *pre_send;
  atclient_connection_send_hook *post_send;
  atclient_connection_send_hook *pre_recv;
  atclient_connection_send_hook *post_recv;
  bool readonly_src;
} atclient_connection_hooks;

typedef struct atclient_connection {
  atclient_connection_type type;

  char host[ATCLIENT_CONSTANTS_HOST_BUFFER_SIZE];
  int port; // example: 64

  // atclient_connection_connect sets this to true and atclient_connection_disconnect sets this to false
  // this does not mean that the connection is still alive, it just means that the connection was established at least
  // once, at some  point, check atclient_connection_is_connected for a live status on the connection
  // _should_be_connected also serves as an internal boolean to check if the following mbedlts contexts have been
  // initialized and need to be freed at the end
  bool _should_be_connected;
  mbedtls_net_context net;
  mbedtls_ssl_context ssl;
  mbedtls_ssl_config ssl_config;
  mbedtls_x509_crt cacert;
  mbedtls_entropy_context entropy;
  mbedtls_ctr_drbg_context ctr_drbg;

  bool _is_hooks_enabled;
  atclient_connection_hooks *hooks;
} atclient_connection;

/**
 * @brief initialize the context for a connection. this function should be called before use of any other function
 *
 * @param ctx the context to initialize
 * @param type the type of connection to initialize,
 * if it is ATCLIENT_CONNECTION_TYPE_ROOT, then '\\n' will be used to check if it is connected.
 * if it is ATCLIENT_CONNECTION_TYPE_ATSERVER, then 'noop:0\r\n' will be used to check if it is connected
 *
 */
void atclient_connection_init(atclient_connection *ctx, atclient_connection_type type);

/**
 * @brief after initializing a connection context, connect to a host and port
 *
 * @param ctx the initialized context
 * @param host the host to connect to
 * @param port the port to connect to
 * @return int 0 on success, otherwise error
 */
int atclient_connection_connect(atclient_connection *ctx, const char *host, const int port);

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
 * @brief free memory allocated by the init function
 *
 * @param ctx the struct which was previously initialized
 */
void atclient_connection_free(atclient_connection *ctx);

/**
 * @brief Initialize the hooks memory allocation
 *
 * @param ctx the struct for the connection
 */
void atclient_connection_enable_hooks(atclient_connection *ctx);

/**
 * @brief Add a hook to be called during the connection lifecycle
 *
 * @param ctx the struct for the connection
 * @param type the hook type you want to add
 * @param hook the hook function itself
 *
 * @return int 0 on success, otherwise error
 */
int atclient_connection_hooks_set(atclient_connection *ctx, atclient_connection_hook_type type, void *hook);

/**
 * @brief Set whether the readonly_src status for all hooks
 *
 * @param ctx the struct for the connection
 * @param readonly_src the new state for readonly_src
 *
 * @note For performance, keep readonly_src set to true if you don't need to write access to src
 */
void atclient_connection_hooks_set_readonly_src(atclient_connection *ctx, bool readonly_src);
#endif
