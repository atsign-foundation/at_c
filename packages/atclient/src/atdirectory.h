#ifndef ATDIRECTORY_H
#define ATDIRECTORY_H

#include "atclient/socket.h"
#include <stdint.h>
#ifdef __cplusplus
extern "C" {
#endif

struct atdirectory_connection {
  struct atclient_tls_socket socket;
  const char *host;
  const uint16_t port;
};

struct atdirectory_connection atdirectory_connection_create(const char *host, const uint16_t port);
void atdirectory_connection_free(struct atdirectory_connection *connection);

int atdirectory_lookup(struct atdirectory_connection *connection, const char *atsign, char **atserver_host,
                       uint16_t *atserver_port);

int atdirectory_lookup_once(const char *atdirectory_host, const uint16_t atdirectory_port, const char *atsign,
                            char **atserver_host, uint16_t *atserver_port);

int atdirectory_parse_host_port_from_buf(const char *buf, size_t len, char **host, uint16_t *port);

#ifdef __cplusplus
}
#endif

#endif
