#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "at_client/connection.h"

int main()
{
    int ret = 1;
    const char *host = "root.atsign.org";
    const int port = 64;

    atclient_connection_ctx ctx;
    ret = atclient_connection_connect(&ctx, host, port);
    printf("Connection successful, hopefully\n");
    printf("atclient_connection_connect: %d\n", ret);

    const size_t dstlen = 1024;
    char *dst = malloc(sizeof(char) * dstlen);
    size_t *olen = malloc(sizeof(size_t));
    const char *command = "smoothalligator\r\n";
    const size_t commandlen = strlen(command);
    ret = atclient_connection_send_data(&ctx, dst, olen, command, commandlen);
    printf("atclient_connection_send_data: %d\n", ret);
    return 0;
}