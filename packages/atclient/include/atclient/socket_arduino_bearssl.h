#ifndef ATCLIENT_ARDUINO_BEARSSL_H
#define ATCLIENT_ARDUINO_BEARSSL_H
#include <atchops/platform.h>
#if defined(ATCLIENT_SOCKET_PROVIDER_ARDUINO_BEARSSL)

#ifdef __cplusplus
extern "C" {
#endif
#include "atclient/socket_shared.h" // IWYU pragma: export
#include <atclient/atclient.h>

// Don't include all of atsdk.h until after these structs are defined
struct atclient_raw_socket {
  uint8_t _; // unused byte to ensure structs are the same size in c/c++
};

struct atclient_tls_socket {
  void *bear_ssl_client;
};

#ifdef __cplusplus
}
#endif

#endif
#endif
