// IWYU pragma: private, include "atclient/socket.h"
// IWYU pragma: friend "socket_mbedtls.*"
#ifndef ATCLIENT_SOCKET_SHARED_H
#define ATCLIENT_SOCKET_SHARED_H
#include <stddef.h>
#ifdef __cplusplus
extern "C" {
#endif

#include <atchops/platform.h>

#if defined(ATCLIENT_SOCKET_PROVIDER_EXTERNAL)
// Noop, this indicates an external socket provider will be linked
#else
#define ATCLIENT_SOCKET_PROVIDER_MBEDTLS
#endif

#ifdef ATCLIENT_SOCKET_PROVIDER_EXTERNAL
#include "../atsdk_socket.h" // IWYU pragma: export
#else
// Defined later based on platform specific implementation
struct atclient_tls_socket;

// Raw socket is only implemented as an internal construct for now
// In the future it will be a supported standalone socket that can
// be used directly
struct atclient_raw_socket;
#endif

enum atclient_socket_read_type {
  // ATCLIENT_SOCKET_READ_NUM_BYTES,
  ATCLIENT_SOCKET_READ_UNTIL_CHAR,
  ATCLIENT_SOCKET_READ_CLEAR_AT_PROMPT,
};

// Define how much we should try to read
struct atclient_socket_read_options {
  enum atclient_socket_read_type type;
  union {
    // size_t num_bytes;
    char until_char;
  };
};

/**
 * @brief Creates read options configured to read until a number of characters have been read
 *
 * @param bytes The number of characters to try to read
 *
 * @return struct atclient_socket_read_options Configuration structure for read operation
 */
// struct atclient_socket_read_options atclient_socket_read_num_bytes(size_t bytes);

/**
 * @brief Creates read options configured to read until a specific character is encountered
 *
 * @param read_until The character to read until (delimiter)
 */
struct atclient_socket_read_options atclient_socket_read_until_char(char read_until);

/**
 * @brief Creates read options configured to read until a specific character is encountered
 */
struct atclient_socket_read_options atclient_socket_read_clear_at_prompt();

#ifdef __cplusplus
}
#endif
#endif
