#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <mbedtls/net_sockets.h>
#include <mbedtls/debug.h>
#include <mbedtls/ssl.h>
#include <mbedtls/entropy.h>
#include <mbedtls/ctr_drbg.h>
#include <mbedtls/x509.h>
#include <mbedtls/base64.h>

#include "at_client/connection.h"

int atclient_connection_connect(atclient_connection_ctx *ctx, const char *host, const int port)
{
    int ret = 1;

    char* portstr = malloc(sizeof(char) * 4);
    sprintf(portstr, "%d", port);

    mbedtls_net_context server_fd;
    mbedtls_entropy_context entropy;
    mbedtls_ctr_drbg_context ctr_drbg;
    mbedtls_ssl_context ssl;
    mbedtls_ssl_config conf;
    mbedtls_x509_crt cacert;

    mbedtls_net_init(&server_fd);
    mbedtls_ssl_init(&ssl);
    mbedtls_ssl_config_init(&conf);
    mbedtls_x509_crt_init(&cacert);
    mbedtls_ctr_drbg_init(&ctr_drbg);
    mbedtls_entropy_init(&entropy);

    // printf("1\n");
    // printf("ssl: %p\n", ssl);
    // printf("conf: %p\n", conf);

    ret = mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func, &entropy, NULL, NULL);
    // printf("mbedtls_ctr_drbg_seed: %d\n", ret);
    if(ret != 0) {
        goto ret;
    }

    ret = mbedtls_x509_crt_parse(&cacert, ROOT_CERT, strlen(ROOT_CERT) + 1);
    // printf("mbedtls_x509_crt_parse: %d\n", ret);
    if(ret != 0) {
        goto ret;
    }

    ret = mbedtls_net_connect(&server_fd, host, portstr, MBEDTLS_NET_PROTO_TCP);
    // printf("mbedtls_net_connect: %d\n", ret);
    if(ret != 0) {
        goto ret;
    }

    ret = mbedtls_ssl_config_defaults(&conf, MBEDTLS_SSL_IS_CLIENT, MBEDTLS_SSL_TRANSPORT_STREAM, MBEDTLS_SSL_PRESET_DEFAULT);
    // printf("mbedtls_ssl_config_defaults: %d\n", ret);
    if(ret != 0) {
        goto ret;
    }

    mbedtls_ssl_conf_authmode(&conf, MBEDTLS_SSL_VERIFY_OPTIONAL);
    mbedtls_ssl_conf_ca_chain(&conf, &cacert, NULL);
    mbedtls_ssl_conf_rng(&conf, mbedtls_ctr_drbg_random, &ctr_drbg);
    // mbedtls_ssl_conf_dbg(conf, my_debug, stdout);

    ret = mbedtls_ssl_setup(&ssl, &conf);
    // printf("mbedtls_ssl_setup: %d\n", ret);
    if(ret != 0) {
        goto ret;
    }

    ret = mbedtls_ssl_set_hostname(&ssl, host);
    // printf("mbedtls_ssl_set_hostname: %d\n", ret);
    if(ret != 0){
        goto ret;
    }

    mbedtls_ssl_set_bio(&ssl, &server_fd, mbedtls_net_send, mbedtls_net_recv, NULL);

    ret = mbedtls_ssl_handshake(&ssl);
    // printf("mbedtls_ssl_handshake: %d\n", ret);
    if(ret != 0) {
        goto ret;
    }

    ret = mbedtls_ssl_get_verify_result(&ssl);
    // printf("mbedtls_ssl_get_verify_result: %d\n", ret);
    if(ret != 0) {
        goto ret;
    }

    ctx->ssl = &ssl;
    ctx->config = &conf;

    printf("(0) ctx->ssl: %p\n", ctx->ssl);
    printf("(0) ctx->config: %p\n", ctx->config);

    size_t read_buflen = 1024;

    unsigned char *read_buf = malloc(sizeof(unsigned char) * read_buflen);
    ret = mbedtls_ssl_read(&ssl, read_buf, read_buflen); // read the initial @ then forget about it
    printf("mbedtls_ssl_read: %d\n", ret);
    printf("\"");
    for(int i = 0; i < 100; i++) {
        printf("%c", read_buf[i]);
    }
    printf("\"\n");

    do {
        ret = mbedtls_ssl_write(&ssl, "smoothalligator\r\n", 17);
        if (ret != MBEDTLS_ERR_SSL_WANT_READ && ret != MBEDTLS_ERR_SSL_WANT_WRITE) {
            break;
        }
    } while(ret <= 0);
    printf("mbedtls_ssl_write: %d\n", ret);

    memset(read_buf, 0, read_buflen);
    ret = mbedtls_ssl_read(&ssl, read_buf, read_buflen);
    printf("mbedtls_ssl_read: %d\n", ret);
    printf("\"");
    for(int i = 0; i < 100; i++) {
        printf("%c", read_buf[i]);
    }
    printf("\"\n");

    goto ret;

    ret: {
        return ret;
    }
}

int atclient_connection_send_data(atclient_connection_ctx *ctx, char *dst, size_t *olen, const char *data, const size_t datalen)
{
    int ret = 1;

    mbedtls_ssl_context *ssl_ptr = (mbedtls_ssl_context *) ctx->ssl;
    mbedtls_ssl_config *conf_ptr = (mbedtls_ssl_config *) ctx->config;

    mbedtls_ssl_context ssl = *ssl_ptr;
    mbedtls_ssl_config conf = *conf_ptr;

    ret = mbedtls_ssl_handshake(&ssl);
    printf("mbedtls_ssl_handshake: %d\n", ret);

    ret = mbedtls_ssl_get_verify_result(&ssl);
    printf("mbedtls_ssl_get_verify_result: %d\n", ret);

    ret = mbedtls_ssl_write(&ssl, (unsigned char *) data, datalen);
    printf("mbedtls_ssl_write: %d\n", ret);

    size_t read_buflen = 1024;
    unsigned char read_buf[read_buflen];

    printf("reading..\n");

    do {
        ret = mbedtls_ssl_read(&ssl, read_buf, read_buflen);
    } while (ret <= 0);
    printf("mbedtls_ssl_read: %d\n", ret);
    size_t l = 0;
    char c;
    while((c = read_buf[l++]) != '\n');

    printf("l: %zu\n", l);
    printf("\"");
    for(int i = 0; i < l; i++){
        printf("%c", read_buf[i]);
    }
    printf("\"\n");
    goto ret;
    ret: {
        return ret;
    }
}

int atclient_connection_disconnect(atclient_connection_ctx *ctx)
{
    int ret = 1;

    goto ret;
    ret: {
        return ret;
    }
}