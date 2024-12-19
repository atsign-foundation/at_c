#ifndef ATCLIENT_SOCKET_H
#define ATCLIENT_SOCKET_H
#include <atchops/platform.h>
#ifndef ATCLIENT_SOCKET_SHARED_H
#include <atclient/socket_shared.h>
#endif
#include <stddef.h>
#include <stdint.h>
#ifdef __cplusplus
extern "C" {
#endif

#ifndef ATCLIENT_SSL_TIMEOUT_EXITCODE

#if defined(ATCLIENT_SOCKET_PROVIDER_MBEDTLS)
#define ATCLIENT_SSL_TIMEOUT_EXITCODE MBEDTLS_ERR_SSL_TIMEOUT

#elif defined(ATCLIENT_SOCKET_PROVIDER_ARDUINO_BEARSSL)
// Most arduino libraries only use -1 or positive integers
#define ATCLIENT_SSL_TIMEOUT_EXITCODE -101

#else
#error "ATCLIENT_ERR_SSL_TIMEOUT is undefined"

#endif

#endif

// IWYU pragma: begin_exports

// Export the appropriate platform specific struct implementation
#if defined(ATCLIENT_SOCKET_PROVIDER_MBEDTLS)
#include "socket_mbedtls.h"
#endif

// IWYU pragma: end_exports

/**
 * @brief Initializes a raw socket
 *
 * @param socket The socket structure to initialize
 */
void atclient_raw_socket_init(struct atclient_raw_socket *socket);

/**
 * @brief Frees resources associated with a network socket
 *
 * @param socket The socket structure to free resources from
 */
void atclient_raw_socket_free(struct atclient_raw_socket *socket);

/**
 * @brief Initializes a tls socket with the specified parameters
 *
 * @param socket The socket structure to initialize
 */
void atclient_tls_socket_init(struct atclient_tls_socket *socket);

/**
 * @brief Configures the SSL on a TLS socket
 *
 * @param ca_pem The X.509 CA certificates in pem format (leave NULL to use the provided default certificates)
 * @param ca_pem_len Length of the ca_pem, ignored if ca_pem is NULL
 *
 * @return 0 on success, non-zero on failure
 *
 * @note Should be called after atclient_tls_socket_init, note that this
 * contains the rest of the initialization operations which have potential
 * to fail
 */
int atclient_tls_socket_configure(struct atclient_tls_socket *socket, unsigned char *ca_pem, size_t ca_pem_len);

/**
 * @brief Frees resources associated with a network socket
 *
 * @param socket The socket structure to free resources from
 */
void atclient_tls_socket_free(struct atclient_tls_socket *socket);

/**
 * @brief Establishes a connection to the specified host and port using the network socket
 *
 * @param socket Pointer to the initialized network socket structure
 * @param host The hostname or IP address to connect to
 * @param port The port number to connect to
 *
 * @return 0 on success, non-zero on failure
 */
int atclient_tls_socket_connect(struct atclient_tls_socket *socket, const char *host, const uint16_t port);

/**
 * @brief Disconnects and closes an established network socket connection
 *
 * @param socket Pointer to the network socket structure to disconnect
 *
 * @return 0 on success, non-zero on failure
 */
int atclient_tls_socket_disconnect(struct atclient_tls_socket *socket);

/**
 * @brief Writes data to an established network socket connection
 *
 * @param socket Pointer to the network socket structure
 * @param value Pointer to the buffer containing data to write
 * @param value_len Length of the data to write in bytes
 *
 * @return 0 on success, non-zero on failure
 */
int atclient_tls_socket_write(struct atclient_tls_socket *socket, const unsigned char *value, size_t value_len);

/**
 * @brief Reads data from an established network socket connection
 *
 * @param socket Pointer to the network socket structure
 * @param value Pointer to the buffer where read data will be stored
 * @param value_len Pointer to store the length of data read in bytes
 * @param options Options which specify the behaviour of reading the data
 *
 * @return 0 on success, non-zero on failure
 */
int atclient_tls_socket_read(struct atclient_tls_socket *socket, unsigned char **value, size_t *value_len,
                             const struct atclient_socket_read_options options);

/**
 * @brief Sets the read timeout for a TLS socket
 *
 * @param socket Pointer to the initialized TLS socket structure
 * @param timeout_ms The timeout value in milliseconds
 */
void atclient_tls_socket_set_read_timeout(struct atclient_tls_socket *socket, const int timeout_ms);

#ifdef __cplusplus
}
#endif
#endif
