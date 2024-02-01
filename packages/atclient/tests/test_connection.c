#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "atclient/connection.h"

int main()
{
    int ret = 1;

    const char *host = "root.atsign.org";
    const int port = 64;

    printf("host: %s\n", host);
    printf("port: %d\n", port);

    atclient_connection connection;
    atclient_connection_init(&connection);

    ret = atclient_connection_connect(&connection, host, port);
    printf("atclient_connection_connect: %d\n", ret);
    if (ret != 0)
    {
        goto exit;
    }

    const unsigned long dstlen = 1024;
    unsigned char dst[dstlen];
    memset(dst, 0, sizeof(unsigned char) * dstlen);
    unsigned long olen = 0;

    const unsigned char *cmd = "colin\r\n";
    const unsigned long cmdlen = strlen(cmd);

    ret = atclient_connection_send(&connection, cmd, cmdlen, dst, dstlen, &olen);
    printf("atclient_connection_send: %d\n", ret);
    if (ret != 0)
    {
        goto exit;
    }

    printf("received: \"%.*s\"\n", (int) olen, dst);

    ret = strncmp((char *) dst, "79b6d83f-5026-5fda-8299-5a0704bd2416.canary.atsign.zone:1029", olen);
    printf("strncmp: %d\n", ret);
    if (ret != 0)
    {
        goto exit;
    }

    goto exit;

exit:
{
    atclient_connection_free(&connection);
    return ret;
}
}