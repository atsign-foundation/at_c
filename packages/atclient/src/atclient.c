
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "atclient/atclient.h"
#include "atclient/atkeys_filereader.h"
#include "atclient/connection.h"
#include "atchops/rsa.h"
#include "atchops/aes_ctr.h"

void atclient_init(atclient_ctx *ctx)
{
    memset(ctx, 0, sizeof(atclient_ctx));
}

int atclient_init_root_connection(atclient_ctx *ctx, const char *root_server, const int root_port)
{
    int ret = 1; // error by default

    atclient_connection_ctx root_connection;
    atclient_connection_init(&root_connection);
    ctx->root_connection = root_connection;

    ret = atclient_connection_connect(&(ctx->root_connection), root_server, root_port);
    if(ret != 0)
    {
        goto exit;
    }

    goto exit;

exit:
{
    return ret;
}
}

int atclient_init_secondary_connection(atclient_ctx *ctx, const char *secondary_server, const int secondary_port)
{
    int ret = 1; // error by default

    atclient_connection_ctx secondary_connection;
    atclient_connection_init(&secondary_connection);
    ctx->secondary_connection = secondary_connection;

    ret = atclient_connection_connect(&(ctx->secondary_connection), secondary_server, secondary_port);
    if(ret != 0)
    {
        goto exit;
    }

    goto exit;

exit: {
    return ret;
}
}

int atclient_pkam_authenticate(atclient_ctx *ctx, const char *atsign, atclient_atkeysfile *atkeysfile)
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
    ret = atclient_connection_send(&(ctx->root_connection), recv, recvlen, &olen, src, strlen(src));
    if(ret != 0)
    {
        goto exit;
    }
    printf("recv: \'%s\'\n", recv);

    // recv is something like 3b419d7a-2fee-5080-9289-f0e1853abb47.swarm0002.atsign.zone:5770
    // store host and port in separate vars
    char *host = (unsigned char *) malloc(sizeof(unsigned char) * 1024);
    char *portstr = (unsigned char *) malloc(sizeof(unsigned char) * 128);
    int port;
    memset(host, 0, sizeof(unsigned char) * 1024);
    memset(portstr, 0, sizeof(unsigned char) * 128);

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

    printf("Host: \'%s\'", host);
    printf("PortStr: \'%s\'\n", portstr);

    // 2. init secondary connection
    ret = atclient_init_secondary_connection(ctx, host, port);
    if(ret != 0)
    {
        goto exit;
    }

    // 3. send pkam auth
    memset(src, 0, sizeof(unsigned char) * srclen);
    memset(recv, 0, sizeof(unsigned char) * recvlen);

    strcat(src, "from:");
    strcat(src, atsign);
    strcat(src, "\r\n");

    ret = atclient_connection_send(&(ctx->secondary_connection), recv, recvlen, &olen, src, strlen(src));
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
    atchops_rsa_privatekey pkamprivatekeystruct;

    const unsigned long pkamprivatekeylen = 4096*16;
    unsigned char *pkamprivatekey = malloc(sizeof(unsigned char) * pkamprivatekeylen);
    memset(pkamprivatekey, 0, pkamprivatekeylen);
    unsigned long pkamprivatekeyolen = 0;

    // printf("self encryption key: \"%s\"\n", atkeysfile->self_encryption_key->key);
    // printf("pkam private key (encrypted): \"%s\"\n", atkeysfile->aes_pkam_private_key->key);
    // printf("pkam private key (encrypted) len: %lu\n", atkeysfile->aes_pkam_private_key->len);

    unsigned char *iv = malloc(sizeof(unsigned char) * 16);
    memset(iv, 0, 16);

    ret = atchops_aes_ctr_decrypt(atkeysfile->self_encryption_key->key, atkeysfile->self_encryption_key->len, 256, iv, 16, atkeysfile->aes_pkam_private_key->key, atkeysfile->aes_pkam_private_key->len, pkamprivatekey, pkamprivatekeylen, &pkamprivatekeyolen);
    // printf("atchops_aes_ctr_decrypt: %d\n", ret);

    // printf("pkam private key (decrypted): \"%s\"\n", pkamprivatekey);
    // printf("pkam private key (decrypted) len: %lu\n", pkamprivatekeyolen);

    ret = atchops_rsa_populate_privatekey(pkamprivatekey, pkamprivatekeyolen, &pkamprivatekeystruct);

    // printf("n: %lu\n", pkamprivatekeystruct.n.len);
    // printf("e: %lu\n", pkamprivatekeystruct.e.len);

    // sign
    memset(recv, 0, recvlen);
    ret = atchops_rsa_sign(pkamprivatekeystruct, ATCHOPS_MD_SHA256, challenge, strlen(challenge), recv, recvlen, &olen);
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

    ret = atclient_connection_send(&(ctx->secondary_connection), recv, recvlen, &olen, src, strlen(src));

    if(ret != 0)
    {
        goto exit;
    }

    printf("pkam response: \"%s\"", recv);

    free(src);
    free(recv);

    goto exit;
exit: {
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