#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "atclient/atclient.h"
#include "atclient/atsign.h"
#include "atclient/atkey.h"
#include "atclient/atkeys.h"
#include "atclient/atkeysfile.h"
#include "atclient/connection.h"
#include "atclient/atutils.h"
#include "atclient/atlogger.h"
#include "atchops/rsa.h"
#include "atchops/aesctr.h"
#include "atchops/iv.h"
#include "uuid4.h"
#include <atchops/constants.h>
#include <atclient/constants.h>

#define HOST_BUFFER_SIZE 1024 // the size of the buffer for the host name for root and secondary

#define TAG "atclient"

void atclient_init(atclient_ctx *ctx, char *atsign_str)
{
    int ret = 1;
    memset(ctx, 0, sizeof(atclient_ctx));

    atsign atsign;
    atsign_init(&atsign, atsign_str);
    ctx->atsign = atsign;

    atclient_atkeys atkeys = load_keys(&ctx->atsign);
    copy_atkeys(&(ctx->atkeys), &atkeys);
}

int atclient_init_root_connection(atclient_ctx *ctx, const char *roothost, const int rootport)
{
    int ret = 1; // error by default

    atclient_connection_init(&(ctx->root_connection));

    ret = atclient_connection_connect(&(ctx->root_connection), roothost, rootport);
    if (ret != 0)
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

int atclient_init_secondary_connection(atclient_connection_ctx *connection, const char *secondaryhost, const int secondaryport)
{
    int ret = 1; // error by default

    atclient_connection_init(connection);
    ret = atclient_connection_connect(connection, secondaryhost, secondaryport);
    if (ret != 0)
    {
        atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atclient_connection_connect: %d\n", ret);
        goto exit;
    }
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_INFO, "atclient_connection_connect: %d. Successfully connected to secondary\n", ret);

    goto exit;

exit:
{
    return ret;
}
}

int atclient_pkam_authenticate(atclient_ctx *ctx, atclient_connection_type type, atclient_atkeys atkeys, const char *atsign)
{
    int ret = 1; // error by default
    atclient_connection_ctx connection;
    switch(type) {
        case ATCLIENT_CONNECTION_TYPE_ROOT:
            printf("Error: root connection can't be used for pkam authentication");
            goto exit;
        case ATCLIENT_CONNECTION_TYPE_SECONDARY:
            connection = ctx->secondary_connection;
        case ATCLIENT_CONNECTION_TYPE_MONITOR:
            connection = ctx->monitor.monitor_connection;
        default:
            connection = ctx->secondary_connection;
    }

    // 1. init root connection
    const unsigned long recvlen = 1024;
    unsigned char *recv = (unsigned char *)malloc(sizeof(unsigned char) * recvlen);
    memset(recv, 0, sizeof(unsigned char) * recvlen);

    unsigned long srclen = 1024;
    unsigned char *src = (unsigned char *)malloc(sizeof(unsigned char) * srclen);
    memset(src, 0, sizeof(unsigned char) * srclen);

    atsign++; // remove @
    memcpy(src, atsign, strlen(atsign));
    memcpy(src + strlen(atsign), "\r\n", 2);
    atsign--;

    unsigned long olen = 0;
    ret = atclient_connection_send(&(ctx->root_connection), src, strlen((char *)src), recv, recvlen, &olen);
    if (ret != 0)
    {
        goto exit;
    }
    // printf("recv: \'%s\'\n", recv);

    // recv is something like 3b419d7a-2fee-5080-9289-f0e1853abb47.swarm0002.atsign.zone:5770
    // store host and port in separate vars
    char *host = (char *)malloc(sizeof(char) * 1024);
    char *portstr = (char *)malloc(sizeof(char) * 16);
    int port;
    memset(host, 0, sizeof(unsigned char) * 1024);
    memset(portstr, 0, sizeof(unsigned char) * 16);

    int i = 0;
    for (; i < olen; i++)
    {
        if (recv[i] == ':')
        {
            break;
        }
        host[i] = recv[i];
    }
    i++;
    for (int j = 0; i < olen; i++)
    {
        portstr[j] = recv[i];
        j++;
    }
    port = atoi(portstr);

    // 2. init secondary connection
    ret = atclient_init_secondary_connection(&connection, host, port);
    // printf("atclient_init_secondary_connection: %d\n", ret);
    if (ret != 0)
    {
        goto exit;
    }

    // 3. send pkam auth
    memset(src, 0, sizeof(unsigned char) * srclen);
    memset(recv, 0, sizeof(unsigned char) * recvlen);

    memcpy(src, "from:", 5);
    memcpy(src + 5, atsign, strlen(atsign));
    memcpy(src + 5 + strlen(atsign), "\r\n", 2);

    ret = atclient_connection_send(&connection, src, strlen((char *)src), recv, recvlen, &olen);
    if (ret != 0)
    {
        goto exit;
    }

    const unsigned long challengelen = 1024;
    unsigned char *challenge = (unsigned char *)malloc(sizeof(unsigned char) * challengelen);
    memset(challenge, 0, challengelen);
    memcpy(challenge, recv, olen);

    // remove data:
    challenge = challenge + 5;
    // remove \r\n@ at the end
    challenge[olen - 5] = '\0';

    // sign
    memset(recv, 0, recvlen);
    ret = atchops_rsa_sign(atkeys.pkamprivatekey, ATCHOPS_MD_SHA256, challenge, strlen((char *)challenge), recv, recvlen, &olen);
    // printf("atchops_rsa_sign: %d\n", ret);
    if (ret != 0)
    {
        goto exit;
    }

    memset(src, 0, srclen);

    memcpy(src, "pkam:", 5);
    memcpy(src + 5, recv, olen);
    memcpy(src + 5 + olen, "\r\n", 2);

    memset(recv, 0, recvlen);

    ret = atclient_connection_send(&connection, src, strlen((char *)src), recv, recvlen, &olen);

    if (ret != 0)
    {
        goto exit;
    }

    goto exit;
exit:
{
    free(src);
    free(recv);
    return ret;
}
}

int get_encryption_key_shared_by_me(atclient_ctx *ctx, const char *recipient_atsign, char *enc_key_shared_by_me)
{
    //  atclient_atkeys atkeys, const char *myatsign
    int ret = 1;

    // llookup:shared_key.recipient_atsign@myatsign
    char *command_prefix = "llookup:shared_key.";
    char *myatsign_with_prefix = ctx->atsign.atsign;
    char *myatsign_without_prefix = ctx->atsign.without_prefix_str;
    char *recipient_atsign_without_prefix = without_prefix(recipient_atsign);

    char *command = (char *)malloc(strlen(command_prefix) + strlen(recipient_atsign_without_prefix) + strlen(myatsign_with_prefix) + 3);
    strcpy(command, command_prefix);
    strcat(command, recipient_atsign_without_prefix);
    strcat(command, myatsign_with_prefix);
    strcat(command, "\r\n");

    const unsigned long recvlen = 1024;
    unsigned char *recv = (unsigned char *)malloc(sizeof(unsigned char) * recvlen);
    memset(recv, 0, sizeof(unsigned char) * recvlen);
    unsigned long olen = 0;

    ret = atclient_connection_send(&(ctx->secondary_connection), command, strlen((char *)command), recv, recvlen, &olen);
    if (ret != 0)
    {
        return ret;
    }

    char *response = recv;

    // Truncate response: "@" + myatsign + "@"
    int response_prefix_len = strlen(myatsign_without_prefix) + 3;
    char *response_prefix = (char *)malloc(response_prefix_len);
    strcpy(response_prefix, "@");
    strcat(response_prefix, myatsign_without_prefix);
    strcat(response_prefix, "@");

    if (starts_with(response_prefix, response))
    {
        response = response + response_prefix_len;
    }
    // printf("response_prefix: '%s'\n", response_prefix);
    if (ends_with(response_prefix, response))
    {
        response[strlen(response) - strlen(response_prefix) - 1] = '\0';
    }

    // does my atSign already have the recipient's shared key?
    if (starts_with("data:", response))
    {

        response = response + 5;

        // 44 + 1
        unsigned long plaintextlen = 45;
        unsigned char *plaintext = malloc(sizeof(unsigned char) * plaintextlen);
        memset(plaintext, 0, plaintextlen);
        unsigned long plaintextolen = 0;

        // printf("key: %s\n", ctx->atkeys.encryptprivatekeystr);

        ret = atchops_rsa_decrypt(ctx->atkeys.encryptprivatekey, (const unsigned char *)response, strlen((char *)response), plaintext, plaintextlen, &plaintextolen);
        if (ret != 0)
        {
            printf("atchops_rsa_decrypt (failed): %d\n", ret);
            return ret;
        }
        memcpy(enc_key_shared_by_me, plaintext, plaintextlen);
    }
    else if (starts_with("error:AT0015-key not found", recv))
    {
        // or do I need to create, store and share a new shared key?
    }
    return 0;
}

int get_encryption_key_shared_by_other(atclient_ctx *ctx, const char *recipient_atsign, char *enc_key_shared_by_other)
{
    int ret = 1;

    // llookup:cached:@myatsign:shared_key@recipient_atsign
    // lookup:shared_key@recipient_atsign
    char *command_prefix = "lookup:shared_key@";
    char *myatsign_with_prefix = ctx->atsign.atsign;
    char *myatsign_without_prefix = ctx->atsign.without_prefix_str;
    char *recipient_atsign_with_prefix = with_prefix(recipient_atsign);
    char *recipient_atsign_without_prefix = without_prefix(recipient_atsign);

    char *command = (char *)malloc(strlen(command_prefix) + strlen(recipient_atsign_without_prefix) + 3);
    strcpy(command, command_prefix);
    strcat(command, recipient_atsign_without_prefix);
    strcat(command, "\r\n");

    const unsigned long recvlen = 1024;
    unsigned char *recv = (unsigned char *)malloc(sizeof(unsigned char) * recvlen);
    memset(recv, 0, sizeof(unsigned char) * recvlen);
    unsigned long olen = 0;

    ret = atclient_connection_send(&(ctx->secondary_connection), command, strlen((char *)command), recv, recvlen, &olen);
    if (ret != 0)
    {
        return ret;
    }

    char *response = recv;

    // Truncate response: "@" + myatsign + "@"
    int response_prefix_len = strlen(myatsign_without_prefix) + 3;
    char *response_prefix = (char *)malloc(response_prefix_len);
    strcpy(response_prefix, "@");
    strcat(response_prefix, myatsign_without_prefix);
    strcat(response_prefix, "@");

    if (starts_with(response_prefix, response))
    {
        response = response + response_prefix_len;
    }
    // printf("response_prefix: '%s'\n", response_prefix);
    if (ends_with(response_prefix, response))
    {
        response[strlen(response) - strlen(response_prefix) - 1] = '\0';
    }

    // does my atSign already have the recipient's shared key?
    if (starts_with("data:", response))
    {

        response = response + 5;

        // 44 + 1
        unsigned long plaintextlen = 45;
        unsigned char *plaintext = malloc(sizeof(unsigned char) * plaintextlen);
        memset(plaintext, 0, plaintextlen);
        unsigned long plaintextolen = 0;

        // int cmp = memcmp(&ctx->atkeys.encryptprivatekey, &atkeys.encryptprivatekey, sizeof(atchops_rsakey_privatekey));
        // printf("Compare: %d\n", cmp);

        ret = atchops_rsa_decrypt(ctx->atkeys.encryptprivatekey, (const unsigned char *)response, strlen((char *)response), plaintext, plaintextlen, &plaintextolen);
        if (ret != 0)
        {
            printf("atchops_rsa_decrypt (failed): %d\n", ret);
            return ret;
        }
        memcpy(enc_key_shared_by_other, plaintext, plaintextlen);
    }
    else if (starts_with("error:AT0015-key not found", recv))
    {
        // or do I need to create, store and share a new shared key?
    }
    return 0;
}

int attalk_send(atclient_ctx *ctx, atclient_atkeys atkeys, const char *myatsign, const char *recipient_atsign, char *enc_key_shared_by_me, char *msg)
{
    const char *aeskeybase64 = enc_key_shared_by_me; // 32 byte key == 256 bits
    const char *plaintext = msg;
    const unsigned long plaintextlen = strlen(plaintext);
    unsigned long olen = 0;

    int ret = 1;
    unsigned char iv[ATCHOPS_IV_SIZE];

    const unsigned long ivbase64len = 26;
    unsigned char *ivbase64 = malloc((sizeof(char) * ivbase64len) + 1);
    memset(ivbase64, 0, ivbase64len + 1);
    ret = atchops_iv_generate_base64(ivbase64, ivbase64len, &olen);
    if (ret != 0)
    {
        printf("atchops_iv_generate (failed): %d\n", ret);
        // goto exit;
    }

    // Build the atkey
    atclient_atkey at_key;
    atclient_atkey_init(&at_key);

    at_key.metadata.ttr = -1;
    at_key.metadata.ivnonce.len = strlen(ivbase64);
    at_key.metadata.ivnonce.str = ivbase64;

    at_key.namespacestr.str = "attalk.ai6bh";
    at_key.sharedby.str = ctx->atsign.atsign;
    at_key.sharedwith.str = with_prefix(recipient_atsign);
    at_key.atkeytype = SHAREDKEY;

    // Send the notification
    const unsigned long recvlen = 1024;
    unsigned char *recv = (unsigned char *)malloc(sizeof(unsigned char) * recvlen);
    memset(recv, 0, sizeof(unsigned char) * recvlen);

    notify(ctx, &at_key, msg, recv, recvlen, "update", NULL);
    // printf("Response: %s\n", recv);

    return 0;
}

int notify(atclient_ctx *ctx, atclient_atkey *at_key, char *value, char *recv, const unsigned long recvlen, char *operation, char *session_uuid)
{
    int ret = 1;
    unsigned long olen = 0;

    // Decode iv
    char *ivbase64 = at_key->metadata.ivnonce.str;
    const unsigned long ivbyteslen = 17;
    char *iv = malloc(ivbyteslen);
    ret = atchops_base64_decode(ivbase64, strlen(ivbase64), iv, ivbyteslen, &olen);
    if (ret != 0)
    {
        // goto exit;
    }

    char *enc_key_shared_by_me = malloc(45);
    get_encryption_key_shared_by_me(ctx, at_key->sharedwith.str, enc_key_shared_by_me);

    // Encrypt message
    unsigned long ciphertextlen = ATSIGN_BUFFER_LENGTH; // sufficient allocation
    unsigned char *ciphertext = malloc(sizeof(unsigned char) * ciphertextlen);
    memset(ciphertext, 0, ciphertextlen);

    ret = atchops_aesctr_encrypt(
        enc_key_shared_by_me,
        strlen(enc_key_shared_by_me),
        ATCHOPS_AES_256,
        iv,
        (unsigned char *)value,
        strlen(value),
        ciphertext,
        ciphertextlen,
        &olen
    );

    if (ret != 0)
    {
        printf("atchops_aesctr_encrypt (failed): %d\n", ret);
        // goto exit;
    }

    // Check UUID
    char *uuid = NULL;
    if (session_uuid != NULL)
    {
        uuid = session_uuid;
    }
    else
    {
        uuid = malloc(UUID4_LEN);
        uuid4_init();
        uuid4_generate(uuid);
    }

    char *metadata_str;
    ret = atclient_atkey_metadata_to_string(&(at_key->metadata), &metadata_str);
    if (ret != 0)
    {
        printf("atclient_atkey_metadata_to_string (failed): %d\n", ret);
        // goto exit;
    }

    // Build notify verb
    const char initial_prefix[] = "notify:id:";
    const char *strings[] = {
        uuid,
        ":",
        operation,
        metadata_str,
        ":",
        at_key->sharedwith.str,
        ":",
        at_key->namespacestr.str,
        ctx->atsign.atsign,
        ":",
        ciphertext,
        "\r\n"};

    int num_strings = sizeof(strings) / sizeof(strings[0]);
    char *command = concatenate_with_prefix(initial_prefix, strings, num_strings);

    // Send notification
    ret = atclient_connection_send(&(ctx->secondary_connection), command, strlen((char *)command), recv, recvlen, &olen);
    if (ret != 0)
    {
        return ret;
    }

    return 0;
}

void atclient_start_monitor(atclient_ctx *ctx, atclient_monitor_connection_ctx *monitor)
{
    if(&(ctx->queue) != NULL)
    {
        if (&(ctx->monitor.monitor_connection) == NULL)
        {
            atclient_monitor_connection_init(&(ctx->monitor), ctx->atsign.atsign);

        }
    }
}

void atclient_free(atclient_ctx *ctx)
{
    atclient_connection_free(&(ctx->root_connection));
    atclient_connection_free(&(ctx->secondary_connection));
}