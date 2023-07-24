
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <mbedtls/ssl.h>
#include <mbedtls/net_sockets.h>
#include <mbedtls/entropy.h>
#include <mbedtls/ctr_drbg.h>
#include "connection.h"

static void my_debug(void *ctx, int level, const char *file, int line, const char *str)
{
    ((void) level);
    fprintf( (FILE *) ctx, "%s:%04d: %s", file, line, str );
    fflush(  (FILE *) ctx  );
}

void atclient_connection_init(atclient_connection_ctx *ctx, const char *host, const int port)
{
    ctx->host = host;
    ctx->port = port;
    ctx->cert_pem = ROOT_CERT;
    ctx->server_fd = malloc(sizeof(mbedtls_net_context));
    ctx->ssl = malloc(sizeof(mbedtls_ssl_context));
    ctx->conf = malloc(sizeof(mbedtls_ssl_config));
    ctx->cacert = malloc(sizeof(mbedtls_x509_crt));
    ctx->entropy = malloc(sizeof(mbedtls_entropy_context));
    ctx->ctr_drbg = malloc(sizeof(mbedtls_ctr_drbg_context));
}

int atclient_connection_connect(atclient_connection_ctx *ctx)
{
    int ret = 1;

    mbedtls_net_init(ctx->server_fd);
    mbedtls_ssl_init(ctx->ssl);
    mbedtls_ssl_config_init(ctx->conf);
    mbedtls_x509_crt_init(ctx->cacert);
    mbedtls_entropy_init(ctx->entropy);
    mbedtls_ctr_drbg_init(ctx->ctr_drbg);

    char *host = ctx->host;
    char *portstr = malloc(sizeof(char) * 6);
    sprintf(portstr, "%d", ctx->port);

    ret = mbedtls_ctr_drbg_seed(ctx->ctr_drbg, mbedtls_entropy_func, ctx->entropy, NULL, NULL);
    if(ret != 0)
    {
        goto exit;
    }
    // printf("mbedtls_ctr_drbg_seed: %d\n", ret);

    ret = mbedtls_x509_crt_parse(ctx->cacert, ROOT_CERT, strlen(ROOT_CERT) + 1);
    if(ret != 0)
    {
        goto exit;
    }
    // printf("mbedtls_x509_crt_parse: %d\n", ret);

    ret = mbedtls_net_connect(ctx->server_fd, host, portstr, MBEDTLS_NET_PROTO_TCP);
    if(ret != 0)
    {
        goto exit;
    }
    // printf("mbedtls_net_connect: %d\n", ret);

    ret = mbedtls_ssl_config_defaults(ctx->conf, MBEDTLS_SSL_IS_CLIENT, MBEDTLS_SSL_TRANSPORT_STREAM, MBEDTLS_SSL_PRESET_DEFAULT);
    if(ret != 0)
    {
        goto exit;
    }
    // printf("mbedtls_ssl_config_defaults: %d\n", ret);

    mbedtls_ssl_conf_ca_chain(ctx->conf, ctx->cacert, NULL);
    mbedtls_ssl_conf_authmode(ctx->conf, MBEDTLS_SSL_VERIFY_REQUIRED);
    mbedtls_ssl_conf_rng(ctx->conf, mbedtls_ctr_drbg_random, ctx->ctr_drbg);
    mbedtls_ssl_conf_dbg(ctx->conf, my_debug, stdout);

    ret = mbedtls_ssl_setup(ctx->ssl, ctx->conf);
    if(ret != 0)
    {
        goto exit;
    }
    // printf("mbedtls_ssl_setup: %d\n", ret);

    ret = mbedtls_ssl_set_hostname(ctx->ssl, host);
    if(ret != 0)
    {
        goto exit;
    }
    // printf("mbedtls_ssl_set_hostname: %d\n", ret);

    mbedtls_ssl_set_bio(ctx->ssl, ctx->server_fd, mbedtls_net_send, mbedtls_net_recv, mbedtls_net_recv_timeout);

    ret = mbedtls_ssl_handshake(ctx->ssl);
    if(ret != 0)
    {
        goto exit;
    }
    // printf("mbedtls_ssl_handshake: %d\n", ret);

    ret = mbedtls_ssl_get_verify_result(ctx->ssl);
    if(ret != 0)
    {
        goto exit;
    }
    // printf("mbedtls_ssl_get_verify_result: %d\n", ret);

    ///////////////////
    // after connect
    ///////////////////

    // const size_t readbuflen = 1024;
    // unsigned char *readbuf;

    // readbuf = malloc(sizeof(unsigned char) * readbuflen);
    // ret = mbedtls_ssl_read(ctx->ssl, readbuf, readbuflen);
    // printf("mbedtls_ssl_read: %d\n", ret);
    // printf("readbuf: \"%s\"\n", readbuf);
    // free(readbuf);

    // ret = mbedtls_ssl_write(ctx->ssl, "smoothalligator\r\n", 17);
    // printf("mbedtls_ssl_write: %d\n", ret);

    const size_t readbuflen = 32;
    unsigned char *readbuf = malloc(sizeof(unsigned char) * readbuflen);
    ret = mbedtls_ssl_read(ctx->ssl, readbuf, readbuflen);
    if(ret < 0)
    {
        goto exit;
    }
    // printf("mbedtls_ssl_read: %d\n", ret);
    free(readbuf);

    free(portstr);

    // ret = mbedtls_ssl_read(ctx->ssl, NULL, 0);
    // printf("mbedtls_ssl_read: %d\n", ret);

    if(ret > 0)
    {
        ret = 0;
    }
    goto exit;
    exit: {
        return ret;
    }
}

int atclient_connection_send(atclient_connection_ctx *ctx, unsigned char *recv, const size_t recvlen, size_t *olen, const unsigned char *src, const size_t srclen)
{
    int ret = 1;
    ret = mbedtls_ssl_write(ctx->ssl, src, srclen);
    if(ret < 0)
    {
        goto exit;
    }
    // printf("mbedtls_ssl_write: %d\n", ret);

    ret = mbedtls_ssl_read(ctx->ssl, recv, recvlen);
    if(ret < 0)
    {
        goto exit;
    }
    // printf("mbedtls_ssl_read: %d\n", ret);

    *olen = 0;
    while(recv[(*olen)++] != '\r');
    (*olen)--; // remove \r

    if(ret > 0)
    {
        ret = 0;
    }

    goto exit;

    exit: {
        return ret;
    }
}


void atclient_connection_free(atclient_connection_ctx *ctx)
{
    free(ctx->server_fd);
    free(ctx->entropy);
    free(ctx->ctr_drbg);
    free(ctx->ssl);
    free(ctx->conf);
    free(ctx->cacert);
    free(ctx);
}