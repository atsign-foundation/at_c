
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "atclient/atclient.h"
#include "atclient/atkeys.h"
#include "atclient/atkeysfile.h"
#include "atclient/connection.h"
#include "atclient/atlogger.h"
#include "atchops/rsa.h"
#include "atchops/aesctr.h"

#define HOST_BUFFER_SIZE 1024 // the size of the buffer for the host name for root and secondary

#define TAG "atclient"

void atclient_init(atclient_ctx *ctx)
{
    memset(ctx, 0, sizeof(atclient_ctx));
}

int atclient_init_root_connection(atclient_ctx *ctx, const char *roothost, const int rootport)
{
    int ret = 1; // error by default

    atclient_connection_init(&(ctx->root_connection));

    ret = atclient_connection_connect(&(ctx->root_connection), roothost, rootport);
    if(ret != 0)
    {
        atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atclient_connection_connect: %d\n", ret);
        goto exit;
    }
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_INFO, "atclient_connection_connect: %d. Successfully connected to root\n", ret);

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
        atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atclient_connection_connect: %d\n", ret);
        goto exit;
    }
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_INFO, "atclient_connection_connect: %d. Successfully connected to secondary\n", ret);

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
    memcpy(src, atsign, strlen(atsign));
    memcpy(src + strlen(atsign), "\r\n", 2);
    atsign--;

    unsigned long olen = 0;
    ret = atclient_connection_send(&(ctx->root_connection), src, strlen((char *) src), recv, recvlen, &olen);
    if(ret != 0)
    {
        goto exit;
    }
    // printf("recv: \'%s\'\n", recv);

    // recv is something like 3b419d7a-2fee-5080-9289-f0e1853abb47.swarm0002.atsign.zone:5770
    // store host and port in separate vars
    char *host = (char *) malloc(sizeof(char) * 1024);
    char *portstr = (char *) malloc(sizeof(char) * 16);
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
    // printf("atclient_init_secondary_connection: %d\n", ret);
    if(ret != 0)
    {
        goto exit;
    }

    // 3. send pkam auth
    memset(src, 0, sizeof(unsigned char) * srclen);
    memset(recv, 0, sizeof(unsigned char) * recvlen);

    memcpy(src, "from:", 5);
    memcpy(src + 5, atsign, strlen(atsign));
    memcpy(src + 5 + strlen(atsign), "\r\n", 2);

    ret = atclient_connection_send(&(ctx->secondary_connection), src, strlen((char *) src), recv, recvlen, &olen);
    if(ret != 0)
    {
        goto exit;
    }

    const unsigned long challengelen = 1024;
    unsigned char *challenge = (unsigned char *) malloc(sizeof(unsigned char) * challengelen);
    memset(challenge, 0, challengelen);
    memcpy(challenge, recv, olen);

    // remove data:
    challenge = challenge + 5;
    // remove \r\n@ at the end
    challenge[olen - 5] = '\0';


    // sign
    memset(recv, 0, recvlen);
    ret = atchops_rsa_sign(atkeys.pkamprivatekey, ATCHOPS_MD_SHA256, challenge, strlen((char *) challenge), recv, recvlen, &olen);
    // printf("atchops_rsa_sign: %d\n", ret);
    if(ret != 0)
    {
        goto exit;
    }


    memset(src, 0, srclen);

    memcpy(src, "pkam:", 5);
    memcpy(src + 5, recv, olen);
    memcpy(src + 5 + olen, "\r\n", 2);


    memset(recv, 0, recvlen);

    ret = atclient_connection_send(&(ctx->secondary_connection), src, strlen((char *) src), recv, recvlen, &olen);

    if(ret != 0)
    {
        goto exit;
    }



    goto exit;
exit: {
    free(src);
    free(recv);
    return ret;
}
}

void atclient_free(atclient_ctx *ctx)
{
    atclient_connection_free(&(ctx->root_connection));
    atclient_connection_free(&(ctx->secondary_connection));
}