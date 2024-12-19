#include "atclient/socket.h"
#include <atchops/platform.h>
#include <string.h>

#if defined(ATCLIENT_SOCKET_PROVIDER_MBEDTLS)

void atclient_raw_socket_init(struct atclient_raw_socket *socket) {
  memset(socket, 0, sizeof(struct atclient_raw_socket));
  mbedtls_net_init(&socket->net);
}

void atclient_raw_socket_free(struct atclient_raw_socket *socket) {
  if (socket != NULL) {
    mbedtls_net_free(&socket->net);
    memset(socket, 0, sizeof(struct atclient_raw_socket));
  }
}

#endif
