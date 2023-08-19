
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <esp_wifi.h>
#include "atclient/connection.h"

#define ATSIGN "@jeremy_0"

static void *without_at_symbol(const char *atsign, char *buf)
{
    int i = 0;
    while (atsign[i] != '\0')
    {
        buf[i] = atsign[i + 1];
        i++;
    }
    buf[i] = '\0';
    return buf;
}

void app_main(void)
{
    esp_wifi_set_mode(WIFI_MODE_STA);

    // 1. initialize buffer to use throughout program
    size_t recvlen = 32768;
    unsigned char *recv = malloc(sizeof(unsigned char) * recvlen);
    size_t olen = 0;

    // 2. connect to root and find secondary address

    // 2a. establish connection to root
    atclient_connection_ctx root_connection;
    atclient_connection_init(&root_connection);
    atclient_connection_connect(&root_connection, "root.atsign.org", 64);
    printf("Connected to root\n");

    // 2b. send atsign without @ symbol to root

    char *atsign_without_at = malloc(sizeof(char) * 100);
    memset(atsign_without_at, 0, 100);
    without_at_symbol(ATSIGN, atsign_without_at);
    strcat(atsign_without_at, "\r\n");
    size_t atsign_without_atlen = strlen(atsign_without_at);

    printf("Sending to root: \"%s\"\n", atsign_without_at);
    atclient_connection_send(&root_connection, recv, recvlen, &olen, (unsigned char *)atsign_without_at, atsign_without_atlen);
    printf("Received from root: \"%.*s\"\n", (int)olen, recv);

    // 2c. parse secondary address
    const size_t secondary_len = 100;
    char *secondary_host = malloc(sizeof(char) * secondary_len);
    char *secondary_port = malloc(sizeof(char) * secondary_len);

    int i = 0, c;
    while ((c = recv[i]) != ':' && i < olen)
    {
        secondary_host[i] = c;
        i++;
    }
    secondary_host[i] = '\0';
    i++;
    int j = 0;
    while ((c = recv[i]) != '\0' && i < olen)
    {
        secondary_port[j] = c;
        i++;
        j++;
    }

    printf("secondary_host: %s\n", secondary_host);
    printf("secondary_port: %s\n", secondary_port);
}