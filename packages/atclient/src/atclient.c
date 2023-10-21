
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "atclient/atclient.h"
#include "atclient/atkeys.h"
#include "atclient/atkeysfile.h"
#include "atclient/connection.h"
#include "atchops/rsa.h"
#include "atchops/aes_ctr.h"

#define HOST_BUFFER_SIZE 1024 // the size of the buffer for the host name for root and secondary

void atclient_init(atclient_ctx *ctx)
{
    memset(ctx, 0, sizeof(atclient_ctx));
    ctx->roothost = (char *) malloc(sizeof(char) * HOST_BUFFER_SIZE);
    ctx->secondaryhost = (char *) malloc(sizeof(char) * HOST_BUFFER_SIZE);
}

int atclient_init_root_connection(atclient_ctx *ctx, const char *roothost, const int rootport)
{
    int ret = 1; // error by default

    atclient_connection_init(&(ctx->root_connection));

    ret = atclient_connection_connect(&(ctx->root_connection), roothost, rootport);
    if(ret != 0)
    {
        goto exit;
    }

    strcpy(ctx->roothost, roothost);
    ctx->rootport = rootport;

    goto exit;

exit:
{
    return ret;
}
}

int atclient_init_secondary_connection(atclient_ctx *ctx, const char *secondaryhost, const int secondaryport)
{
    int ret = 1; // error by default

    atclient_connection_init(&(ctx->secondary_connection));
    ret = atclient_connection_connect(&(ctx->secondary_connection), secondaryhost, secondaryport);
    if(ret != 0)
    {
        goto exit;
    }

    strcpy(ctx->secondaryhost, secondaryhost);
    ctx->secondaryport = secondaryport;

    goto exit;

exit: {
    return ret;
}
}

int atclient_pkam_authenticate(atclient_ctx *ctx, atclient_atkeys atkeys, const char *atsign)
{
    int ret = 1; // error by default

    // 1. init root connection
    const unsigned long recvlen = 1024;
    unsigned char *recv = (unsigned char *) malloc(sizeof(unsigned char) * recvlen);
    memset(recv, 0, sizeof(unsigned char) * recvlen);
    unsigned long srclen = 1024;
    unsigned char *src = (unsigned char *) malloc(sizeof(unsigned char) * srclen);
    memset(src, 0, sizeof(unsigned char) * srclen);
    atsign++; // remove @
    strcat(src, atsign);
    strcat(src, "\r\n");
    atsign--;

    unsigned long olen = 0;
    ret = atclient_connection_send(&(ctx->root_connection), src, strlen(src), recv, recvlen, &olen);
    if(ret != 0)
    {
        goto exit;
    }
    printf("recv: \'%s\'\n", recv);

    // recv is something like 3b419d7a-2fee-5080-9289-f0e1853abb47.swarm0002.atsign.zone:5770
    // store host and port in separate vars
    char *host = (unsigned char *) malloc(sizeof(unsigned char) * 1024);
    char *portstr = (unsigned char *) malloc(sizeof(unsigned char) * 16);
    int port;
    memset(host, 0, sizeof(unsigned char) * 1024);
    memset(portstr, 0, sizeof(unsigned char) * 16);

    int i = 0;
    for(; i < olen; i++)
    {
        if(recv[i] == ':')
        {
            break;
        }
        host[i] = recv[i];
    }
    i++;
    for(int j = 0; i < olen; i++)
    {
        portstr[j] = recv[i];
        j++;
    }
    port = atoi(portstr);

    // 2. init secondary connection
    ret = atclient_init_secondary_connection(ctx, host, port);
    if(ret != 0)
    {
        goto exit;
    }
    // printf("Established connection with secondary: %s:%d\n", host, port);

    // 3. send pkam auth
    memset(src, 0, sizeof(unsigned char) * srclen);
    memset(recv, 0, sizeof(unsigned char) * recvlen);

    strcat(src, "from:");
    strcat(src, atsign);
    strcat(src, "\r\n");

    ret = atclient_connection_send(&(ctx->secondary_connection), src, strlen(src), recv, recvlen, &olen);
    if(ret != 0)
    {
        goto exit;
    }
    printf("challenge: \'%s\'\n", recv);

    const unsigned long challengelen = 1024;
    unsigned char *challenge = (unsigned char *) malloc(sizeof(unsigned char) * challengelen);
    memset(challenge, 0, challengelen);
    strcpy(challenge, recv);

    // remove data:
    challenge = challenge + 5;
    // remove \r\n@ at the end
    challenge[olen - 5] = '\0';

    printf("challenge: \'%s\'\n", challenge);

    // sign
    memset(recv, 0, recvlen);
    ret = atchops_rsa_sign(atkeys.pkamprivatekey, ATCHOPS_MD_SHA256, challenge, strlen(challenge), recv, recvlen, &olen);
    printf("atchops_rsa_sign: %d\n", ret);
    if(ret != 0)
    {
        goto exit;
    }

    printf("signature: \"%.*s\"\n", (int) olen, recv);

    memset(src, 0, srclen);

    strcat(src, "pkam:");
    strcat(src, recv);
    strcat(src, "\r\n");

    printf("pkam command: %d | \"%s\"\n", strlen(src), src);

    memset(recv, 0, recvlen);

    ret = atclient_connection_send(&(ctx->secondary_connection), src, strlen(src), recv, recvlen, &olen);

    if(ret != 0)
    {
        goto exit;
    }

    printf("pkam response: \"%s\"\n", recv);


    goto exit;
exit: {
    free(src);
    free(recv);
    return ret;
}
}

int atclient_put(atclient_ctx *ctx, const char *key, const char *value)
{
    return 1; // not implemented
}

int atclient_get(atclient_ctx *ctx, const char *key, char *value, const unsigned long valuelen)
{
    return 1; // not implemented
}

int atclient_delete(atclient_ctx *ctx, const char *key)
{
    return 1; // not implemented
}

void atclient_free(atclient_ctx *ctx)
{
    return; // not implemented
}