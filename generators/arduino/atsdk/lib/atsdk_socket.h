#ifndef ATSDK_SOCKET_H
#define ATSDK_SOCKET_H
#ifdef __cplusplus
extern "C" {
#endif

#include "./atclient/atclient.h"
#include "./atclient/socket.h"
#include <ArduinoBearSSL.h>

void atclient_setup_bearssl(struct atclient *, BearSSLClient *ssl_client);

#ifdef __cplusplus
}
#endif
#endif
