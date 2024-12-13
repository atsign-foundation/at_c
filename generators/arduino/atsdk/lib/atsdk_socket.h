#ifndef ATSDK_SOCKET_H
#define ATSDK_SOCKET_H

#define ATCLIENT_SOCKET_PROVIDER_EXTERNAL // disables mbedtls for sockets
#ifdef __clang__                          // For development to supress irrelevant errors
// Include the relative atlogger header when in development mode
#include "../../../../packages/atclient/include/atclient/socket.h"        // IWYU pragma: export
#include "../../../../packages/atclient/include/atclient/socket_shared.h" // IWYU pragma: export

#include <cstdint>
class WiFiClient {
public:
  // virtual int connect(IPAddress ip, uint16_t port);
  virtual int connect(const char *host, uint16_t port);
  // int connectSSL(IPAddress ip, uint16_t port);
  int connectSSL(const char *host, uint16_t port);
  virtual void stop();

  virtual explicit operator bool();
  virtual uint8_t connected();
  uint8_t status();

  // IPAddress remoteIP();
  uint16_t remotePort();

  virtual size_t write(uint8_t);
  virtual size_t write(const uint8_t *buf, size_t size);
  virtual void flush();

  virtual int available();
  virtual int read();
  virtual int read(uint8_t *buf, size_t size);
  virtual int peek();

  // using Print::write;

  void setSocketTimeout(unsigned long timeout);
};
extern void delay(int);
#endif

#ifdef __cplusplus
extern "C" {
#endif

#ifndef ATCLIENT_SOCKET_PROVIDER_EXTERNAL // Actual compile time includes
#include "atclient/socket_shared.h"
#endif

// Don't include all of atsdk.h until after these structs are defined
struct atclient_raw_socket {
  void *_; // unused pointer to ensure structs are the same size in c/c++
};

struct atclient_tls_socket {
  int handle;
};

#ifdef __cplusplus
}
#endif

#endif
