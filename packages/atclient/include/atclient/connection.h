#ifndef ATCLIENT_CONNECTION_H
#define ATCLIENT_CONNECTION_H

#include <mbedtls/ssl.h>
#include <mbedtls/net_sockets.h>
#include <mbedtls/entropy.h>
#include <mbedtls/ctr_drbg.h>

typedef struct atclient_connection_ctx {
    char *host; // assume null terminated, example: "root.atsign.org"
    int port; // example: 64
    mbedtls_net_context net;
    mbedtls_ssl_context ssl;
    mbedtls_ssl_config ssl_config;
    mbedtls_x509_crt cacert;
    mbedtls_entropy_context entropy;
    mbedtls_ctr_drbg_context ctr_drbg;
} atclient_connection_ctx;

/**
 * @brief initialize the context for a connection. this function should be called before use of any other function
 * 
 * @param ctx the context to initialize
 */
void atclient_connection_init(atclient_connection_ctx *ctx);

/**
 * @brief after initializing a connection context, connect to a host and port
 * 
 * @param ctx the initialized context
 * @param host the host to connect to
 * @param port the port to connect to
 * @return int 0 on success, otherwise error
 */
int atclient_connection_connect(atclient_connection_ctx *ctx, const char *host, const int port);

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
int atclient_connection_send(atclient_connection_ctx *ctx, const unsigned char *src, const unsigned long srclen, unsigned char *recv, const unsigned long recvlen, unsigned long *olen);

/// @brief 
/// @param ctx the connection which was initialized (via the init function) and connected (via the connect function)
/// @param recv the buffer to receive data
/// @param recvlen the length of the buffer to receive data
/// @return int 0 on success, otherwise error
int atclient_connection_readline(atclient_connection_ctx *ctx, char *recv, size_t recvlen);

/**
 * @brief disconnect a connection
 * 
 * @param ctx the connection to disconnect
 * @return int 0 on success, otherwise error
 */
int atclient_connection_disconnect(atclient_connection_ctx *ctx);

/**
 * @brief checks if the connection is connected
 * 
 * @param ctx the connection to check
 * @return int 1 if connected, 0 if not connected, negative on error
 */
int atclient_connection_is_connected(atclient_connection_ctx *ctx);

/**
 * @brief free memory allocated by the init function
 * 
 * @param ctx the struct which was previously initialized
 */
void atclient_connection_free(atclient_connection_ctx *ctx);

#endif