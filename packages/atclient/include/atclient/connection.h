#ifndef ATCLIENT_CONNECTION_H
#define ATCLIENT_CONNECTION_H

#include "atclient/atstr.h"
#include "atclient/constants.h"
#include <mbedtls/ctr_drbg.h>
#include <mbedtls/entropy.h>
#include <mbedtls/net_sockets.h>
#include <mbedtls/ssl.h>

typedef struct atclient_connection {
  // char *host; // assume null terminated, example: "root.atsign.org"
  char host[ATCLIENT_CONSTANTS_HOST_BUFFER_SIZE];
  int port; // example: 64
  mbedtls_net_context net;
  mbedtls_ssl_context ssl;
  mbedtls_ssl_config ssl_config;
  mbedtls_x509_crt cacert;
  mbedtls_entropy_context entropy;
  mbedtls_ctr_drbg_context ctr_drbg;
} atclient_connection;

/**
 * @brief initialize the context for a connection. this function should be called before use of any other function
 *
 * @param ctx the context to initialize
 */
void atclient_connection_init(atclient_connection *ctx);

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
 * @param srclen the length of the data to send
 * @param recv the buffer to receive data
 * @param recvlen the length of the buffer to receive data
 * @param olen the length of the data received
 * @return int 0 on success, otherwise error
 */
int atclient_connection_send(atclient_connection *ctx, const unsigned char *src, const unsigned long srclen,
                             unsigned char *recv, const unsigned long recvlen, unsigned long *olen);

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
 * @return int 1 if connected, 0 if not connected, negative on error
 */
int atclient_connection_is_connected(atclient_connection *ctx);

/**
 * @brief free memory allocated by the init function
 *
 * @param ctx the struct which was previously initialized
 */
void atclient_connection_free(atclient_connection *ctx);

/**
 * @brief get the host and port from a url
 *
 * @param host a pointer to an atclient_atstr to store the host, will hold "root.atsign.org" after the function call,
 * for example. Assumed that this is already initialized via atclient_atstr_init(&host)
 * @param port a pointer to an int to store the port, will hold 64 after the function call, for example
 * @param url the url to parse (example "root.atsign.org:64")
 * @return int 0 on success, otherwise error
 */
int atclient_connection_get_host_and_port(atclient_atstr *host, int *port, const atclient_atstr url);

#endif