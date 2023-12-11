
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <mbedtls/ssl.h>
#include <mbedtls/net_sockets.h>
#include <mbedtls/entropy.h>
#include <mbedtls/ctr_drbg.h>
#include "atclient/atlogger.h"
#include "atclient/cacerts.h"
#include "atclient/connection.h"
#include "atclient/constants.h"

#define TAG "connection"

#define HOST_BUFFER_SIZE 1024 // the size of the buffer for the host name

/* Concatenation of all available CA certificates in PEM format */
const char cas_pem[] =
    LETS_ENCRYPT_ROOT
    GOOGLE_GLOBAL_SIGN
    GOOGLE_GTS_ROOT_R1
    GOOGLE_GTS_ROOT_R2
    GOOGLE_GTS_ROOT_R3
    GOOGLE_GTS_ROOT_R4
    ZEROSSL_INTERMEDIATE
    "";
const size_t cas_pem_len = sizeof(cas_pem);

static void my_debug(void *ctx, int level, const char *file, int line, const char *str)
{
    ((void)level);
    fprintf((FILE *)ctx, "%s:%04d: %s", file, line, str);
    fflush((FILE *)ctx);
}

void atclient_connection_init(atclient_connection_ctx *ctx)
{
    memset(ctx, 0, sizeof(atclient_connection_ctx));
    ctx->host = (char *)malloc(sizeof(char) * HOST_BUFFER_SIZE);
    ctx->port = -1;

    mbedtls_net_init(&(ctx->net));
    mbedtls_ssl_init(&(ctx->ssl));
    mbedtls_ssl_config_init(&(ctx->ssl_config));
    mbedtls_x509_crt_init(&(ctx->cacert));
    mbedtls_entropy_init(&(ctx->entropy));
    mbedtls_ctr_drbg_init(&(ctx->ctr_drbg));
}

int atclient_connection_connect(atclient_connection_ctx *ctx, const char *host, const int port)
{
    int ret = 1;

    strcpy(ctx->host, host); // assume null terminated, example: "root.atsign.org"
    ctx->port = port;        // example: 64

    char *portstr = (char *) malloc(sizeof(char) * 6);
    sprintf(portstr, "%d", ctx->port);

    ret = mbedtls_ctr_drbg_seed(&(ctx->ctr_drbg), mbedtls_entropy_func, &(ctx->entropy), NULL, NULL);
    // printf("mbedtls_ctr_drbg_seed: %d\n", ret);
    if (ret != 0)
    {
        goto exit;
    }

    ret = mbedtls_x509_crt_parse(&(ctx->cacert), cas_pem, cas_pem_len);
    if (ret != 0) 
    {
        goto exit;
    }

    ret = mbedtls_net_connect(&(ctx->net), host, portstr, MBEDTLS_NET_PROTO_TCP);
    // printf("mbedtls_net_connect: %d\n", ret);
    if (ret != 0)
    {
        goto exit;
    }

    ret = mbedtls_ssl_config_defaults(&(ctx->ssl_config), MBEDTLS_SSL_IS_CLIENT, MBEDTLS_SSL_TRANSPORT_STREAM, MBEDTLS_SSL_PRESET_DEFAULT);
    // printf("mbedtls_ssl_config_defaults: %d\n", ret);
    if (ret != 0)
    {
        goto exit;
    }

    mbedtls_ssl_conf_ca_chain(&(ctx->ssl_config), &(ctx->cacert), NULL);
    mbedtls_ssl_conf_authmode(&(ctx->ssl_config), MBEDTLS_SSL_VERIFY_REQUIRED);
    mbedtls_ssl_conf_rng(&(ctx->ssl_config), mbedtls_ctr_drbg_random, &(ctx->ctr_drbg));
    mbedtls_ssl_conf_dbg(&(ctx->ssl_config), my_debug, stdout);

    ret = mbedtls_ssl_setup(&(ctx->ssl), &(ctx->ssl_config));
    // printf("mbedtls_ssl_setup: %d\n", ret);
    if (ret != 0)
    {
        goto exit;
    }

    ret = mbedtls_ssl_set_hostname(&(ctx->ssl), host);
    // printf("mbedtls_ssl_set_hostname: %d\n", ret);
    if (ret != 0)
    {
        goto exit;
    }

    mbedtls_ssl_set_bio(&(ctx->ssl), &(ctx->net), mbedtls_net_send, mbedtls_net_recv, mbedtls_net_recv_timeout);

    ret = mbedtls_ssl_handshake(&(ctx->ssl));
    // printf("mbedtls_ssl_handshake: %d\n", ret);
    if (ret != 0)
    {
        goto exit;
    }

    ret = mbedtls_ssl_get_verify_result(&(ctx->ssl));
    // printf("mbedtls_ssl_get_verify_result: %d\n", ret);
    if (ret != 0)
    {
        goto exit;
    }

    // ===============
    // after connect
    // ===============

    const unsigned long readbuflen = 128;
    unsigned char *readbuf = malloc(sizeof(unsigned char) * readbuflen);
    memset(readbuf, 0, readbuflen);

    // read anything that was already sent
    ret = mbedtls_ssl_read(&(ctx->ssl), readbuf, readbuflen);
    if (ret < 0)
    {
        goto exit;
    }

    // press enter
    ret = mbedtls_ssl_write(&(ctx->ssl), (const unsigned char *)"\r\n", 2);
    if (ret < 0)
    {
        goto exit;
    }

    // read anything that was sent
    ret = mbedtls_ssl_read(&(ctx->ssl), readbuf, readbuflen);
    if (ret < 0)
    {
        goto exit;
    }

    // now we are guaranteed a blank canvas
    
    if (ret > 0)
    {
        ret = 0; // a positive exit code is not an error
    }

    goto exit;

exit:
{
    free(readbuf);
    free(portstr);
    return ret;
}
}

int atclient_connection_send(atclient_connection_ctx *ctx, const unsigned char *src, const unsigned long srclen, unsigned char *recv, const unsigned long recvlen, unsigned long *olen)
{
    int ret = 1;
    ret = mbedtls_ssl_write(&(ctx->ssl), src, srclen);
    if (ret < 0)
    {
        goto exit;
    }
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_INFO, "\tSENT: \"%.*s\"\n", (int) srclen, src);

    memset(recv, 0, recvlen);
    int found = 0;
    unsigned long l = 0;
    do
    {
        ret = mbedtls_ssl_read(&(ctx->ssl), recv + l, recvlen - l);
        if (ret < 0)
        {
            goto exit;
        }
        l = l + ret;

        // printf("*(recv+%lu) == %.2x == %c\n", l-1, (unsigned char) *(recv + l-1), (unsigned char) *(recv + l-1));
        // printf("*(recv+%lu) == %.2x == %c\n", l, (unsigned char) *(recv + l), (unsigned char) *(recv + l));

        // printf("\\n: %.2x\n", '\n');

        for (int i = l; i >= l - ret && i >= 0; i--)
        {
            // printf("i: %d c: %.2x\n", i, (unsigned char) *(recv + i));
            if (*(recv + i) == '\n')
            {
                *olen = i;
                found = 1;
                break;
            }
        }
        if (found == 1)
        {
            break;
        }

        // size_t bytesavail = mbedtls_ssl_get_bytes_avail(ctx->ssl);
        // printf("bytes_avail: %lu\n", bytesavail);
    } while (ret == MBEDTLS_ERR_SSL_WANT_READ || found == 0);

    if (ret < 0)
    {
        goto exit;
    }
    // printf("mbedtls_ssl_read: %d\n", ret);

    *olen = 0;
    while (recv[(*olen)] != '\r' && recv[(*olen)] != '\n')
    {
        *olen = *olen + 1;
    }

    if (ret > 0)
    {
        ret = 0;
    }
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_INFO, "\tRECV: \"%.*s\"\n", (int) *olen, recv);

    goto exit;

exit:
{
    return ret;
}
}

int atclient_connection_readline(atclient_connection_ctx *ctx, char *recv, size_t recvlen) {
    char c;
    int ret;
    size_t index = 0;

    do {
        if(index >= recvlen - 1) {
            break;
        }

        ret = mbedtls_ssl_read(&(ctx->ssl), (unsigned char *)&c, 1);
        if(ret == 1) {
            recv[index++] = c;
        } else {
            printf("readline error: %d\n", ret);
            return ret;
        }
    } while(c != '\n');

    recv[index] = '\0';

    return 0;
}

int atclient_connection_disconnect(atclient_connection_ctx *ctx)
{
    int ret = 0;
    do {
        ret = mbedtls_ssl_close_notify(&(ctx->ssl));
    } while (ret == MBEDTLS_ERR_SSL_WANT_WRITE);
    ret = 0;

    atclient_connection_free(ctx);
    return ret;
}

int atclient_connection_is_connected(atclient_connection_ctx *ctx)
{
    int ret = 0; // false by default
    const char *cmd = "\r\n";
    const unsigned long cmdlen = strlen(cmd);
    const unsigned long recvlen = 128;
    unsigned char *recv = malloc(sizeof(unsigned char) * recvlen);
    memset(recv, 0, recvlen);
    unsigned long olen = 0;

    ret = atclient_connection_send(ctx, (const unsigned char *)cmd, cmdlen, recv, recvlen, &olen);
    if (ret != 0)
    {
        goto exit;
    }

    if (olen > 0)
    {
        ret = 1; // true
    }
    else
    {
        ret = 0; // false
    }

    goto exit;

exit: {
    return ret;
}
}

void atclient_connection_free(atclient_connection_ctx *ctx)
{
    mbedtls_net_free(&(ctx->net));
    mbedtls_ssl_free(&(ctx->ssl));
    mbedtls_ssl_config_free(&(ctx->ssl_config));
    mbedtls_x509_crt_free(&(ctx->cacert));
    mbedtls_ctr_drbg_free(&(ctx->ctr_drbg));
    mbedtls_entropy_free(&(ctx->entropy));
    free(ctx->host);
}