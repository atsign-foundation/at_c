#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "at_client/connection.h"

int main()
{
    int ret = 1;

    const char *host = "root.atsign.org";
    const int port = 64;

    atclient_connection_ctx *ctx = malloc(sizeof(atclient_connection_ctx));
    atclient_connection_init(ctx, host, port);
    ret = atclient_connection_connect(ctx);
    if (ret != 0)
        goto exit;
    // printf("atclient_connection_connect: %d\n", ret);

    const size_t dstlen = 1024;
    char *dst = malloc(sizeof(char) * dstlen);
    size_t *olen = malloc(sizeof(size_t));
    const char *cmd = "colin\r\n";
    const size_t cmdlen = strlen(cmd);
    ret = atclient_connection_send(ctx, dst, dstlen, olen, cmd, cmdlen);
    if (ret != 0)
        goto exit;
    // printf("atclient_connection_send_data: %d\n", ret);

    // printf("\"");
    // for(int i = 0; i < *olen; i++)
    // {
    //     printf("%c", dst[i]);
    // }
    // printf("\"\n");

    ret = strncmp(dst, "79b6d83f-5026-5fda-8299-5a0704bd2416.canary.atsign.zone:1029", *olen);
    if(ret != 0)
        goto exit;

    free(dst);
    free(olen);
    atclient_connection_free(ctx);

    exit: {
        return ret;
    }
}