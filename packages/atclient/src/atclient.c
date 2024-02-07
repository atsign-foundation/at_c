#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <mbedtls/md.h>
#include <atchops/rsa.h>
#include <atchops/aesctr.h>
#include "atclient/atclient.h"
#include "atclient/atkeys.h"
#include "atclient/atkeysfile.h"
#include "atclient/connection.h"
#include "atclient/atlogger.h"
#include "atclient/atstr.h"
#include "atclient/atbytes.h"
#include "atclient/atsign.h"
#include "3rdparty/uuid4/include/uuid4.h"

#define HOST_BUFFER_SIZE 1024 // the size of the buffer for the host name for root and secondary

#define TAG "atclient"

void atclient_init(atclient *ctx)
{
    memset(ctx, 0, sizeof(atclient));
}

int atclient_start_root_connection(atclient *ctx, const char *roothost, const int rootport)
{
    int ret = 1; // error by default

    atclient_connection_init(&(ctx->root_connection));

    ret = atclient_connection_connect(&(ctx->root_connection), roothost, rootport);
    if(ret != 0)
    {
        atclient_atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atclient_connection_connect: %d\n", ret);
        goto exit;
    }
    atclient_atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_INFO, "atclient_connection_connect: %d. Successfully connected to root\n", ret);

    goto exit;

exit:
{
    return ret;
}
}

int atclient_start_secondary_connection(atclient *ctx, const char *secondaryhost, const int secondaryport)
{
    int ret = 1; // error by default

    atclient_connection_init(&(ctx->secondary_connection));
    ret = atclient_connection_connect(&(ctx->secondary_connection), secondaryhost, secondaryport);
    if(ret != 0)
    {
        atclient_atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atclient_connection_connect: %d\n", ret);
        goto exit;
    }
    atclient_atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_INFO, "atclient_connection_connect: %d. Successfully connected to secondary\n", ret);

    goto exit;

exit: {
    return ret;
}
}

int atclient_pkam_authenticate(atclient *ctx, const atclient_atkeys atkeys, const char *atsign, const unsigned long atsignlen)
{
    int ret = 1; // error by default

    // 1. init root connection
    const unsigned long srclen = 1024;
    atclient_atbytes src;
    atclient_atbytes_init(&src, srclen);

    const unsigned long recvlen = 1024;
    atclient_atbytes recv;
    atclient_atbytes_init(&recv, recvlen);

    const unsigned long withoutatlen = 1024;
    atclient_atstr withoutat;
    atclient_atstr_init(&withoutat, withoutatlen);

    const unsigned long urllen = 256;
    atclient_atstr url;
    atclient_atstr_init(&url, 256);

    atclient_atstr host;
    atclient_atstr_init(&host, 256);
    int port = 0;

    const unsigned long atsigncmdlen = 1024;
    atclient_atstr atsigncmd;
    atclient_atstr_init(&atsigncmd, atsigncmdlen);

    const unsigned long fromcmdlen = 1024;
    atclient_atstr fromcmd;
    atclient_atstr_init(&fromcmd, fromcmdlen);

    const unsigned long challengelen = 1024;
    atclient_atstr challenge;
    atclient_atstr_init(&challenge, challengelen);

    const unsigned long challengewithoutdatalen = 1024;
    atclient_atstr challengewithoutdata;
    atclient_atstr_init(&challengewithoutdata, challengewithoutdatalen);

    const unsigned long challengebyteslen = 1024;
    atclient_atbytes challengebytes;
    atclient_atbytes_init(&challengebytes, challengebyteslen);

    const unsigned long pkamcmdlen = 1024;
    atclient_atstr pkamcmd;
    atclient_atstr_init(&pkamcmd, pkamcmdlen);

    ret = atclient_atsign_without_at_symbol(withoutat.str, withoutat.len, &(withoutat.olen), atsign, atsignlen);
    if(ret != 0)
    {
        atclient_atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atclient_atsign_without_at_symbol: %d\n", ret);
        goto exit;
    }

    ret = atclient_atstr_set_literal(&atsigncmd, "%.*s\r\n", (int) withoutat.olen, withoutat.str);
    if(ret != 0)
    {
        atclient_atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atclient_atstr_set_literal: %d\n", ret);
        goto exit;
    }

    ret = atclient_atbytes_convert_atstr(&src, atsigncmd);
    if(ret != 0)
    {
        atclient_atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atclient_atbytes_convert_atstr: %d\n", ret);
        goto exit;
    }

    ret = atclient_connection_send(&(ctx->root_connection), src.bytes, src.olen, recv.bytes, recv.len, &(recv.olen));
    if(ret != 0)
    {
        atclient_atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atclient_connection_send: %d\n | failed to send: %.*s\n", ret, withoutat.olen, withoutat);
        goto exit;
    }

    // 2. init secondary connection
    // recv is something like 3b419d7a-2fee-5080-9289-f0e1853abb47.swarm0002.atsign.zone:5770
    // store host and port in separate vars
    ret = atclient_atstr_set_literal(&url, "%.*s", (int) recv.olen, recv.bytes);
    if(ret != 0)
    {
        atclient_atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atclient_atstr_set_literal: %d\n", ret);
        goto exit;
    }

    ret = atclient_connection_get_host_and_port(&host, &port, url);
    if(ret != 0)
    {
        atclient_atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atclient_connection_get_host_and_port: %d | failed to parse url %.*s\n", ret, recv.olen, recv.bytes);
        goto exit;
    }

    ret = atclient_start_secondary_connection(ctx, host.str, port);
    if(ret != 0)
    {
        atclient_atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atclient_start_secondary_connection: %d\n", ret);
        goto exit;
    }

    // 3. send pkam auth
    ret = atclient_atstr_set_literal(&fromcmd, "from:%.*s\r\n", (int) withoutat.olen, withoutat.str);
    if(ret != 0)
    {
        atclient_atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atclient_atstr_set_literal: %d\n", ret);
        goto exit;
    }

    ret = atclient_atbytes_convert(&src, fromcmd.str, fromcmd.olen);
    if(ret != 0)
    {
        atclient_atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atclient_atbytes_convert: %d\n", ret);
        goto exit;
    }

    ret = atclient_connection_send(&(ctx->secondary_connection), src.bytes, src.olen, recv.bytes, recv.len, &(recv.olen));
    if(ret != 0)
    {
        atclient_atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atclient_connection_send: %d\n", ret);
        goto exit;
    }

    ret = atclient_atstr_set_literal(&challenge, "%.*s", (int) recv.olen, recv.bytes);
    if(ret != 0)
    {
        atclient_atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atclient_atstr_set_literal: %d\n", ret);
        goto exit;
    }

    // remove "data:" prefix
    ret = atclient_atstr_substring(&challengewithoutdata, challenge, 5, challenge.olen);
    if(ret != 0)
    {
        atclient_atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atclient_atstr_substring: %d\n | failed to remove \'data:\' prefix", ret);
        goto exit;
    }

    // sign
    atclient_atbytes_reset(&recv);
    ret = atclient_atbytes_convert_atstr(&challengebytes, challengewithoutdata);
    if(ret != 0)
    {
        atclient_atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atclient_atbytes_convert_atstr: %d\n", ret);
        goto exit;
    }
    ret = atchops_rsa_sign(atkeys.pkamprivatekey, MBEDTLS_MD_SHA256, challengebytes.bytes, challengebytes.olen, recv.bytes, recv.len, &recv.olen);
    if(ret != 0)
    {
        atclient_atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atchops_rsa_sign: %d\n", ret);
        goto exit;
    }

    ret = atclient_atstr_set_literal(&pkamcmd, "pkam:%.*s\r\n", (int) recv.olen, recv.bytes);
    if(ret != 0)
    {
        atclient_atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atclient_atstr_set_literal: %d\n", ret);
        goto exit;
    }
    
    atclient_atbytes_reset(&recv);
    ret = atclient_atbytes_convert_atstr(&src, pkamcmd);
    if(ret != 0)
    {
        atclient_atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atclient_atbytes_convert_atstr: %d\n", ret);
        goto exit;
    }

    ret = atclient_connection_send(&(ctx->secondary_connection), src.bytes, src.olen, recv.bytes, recv.len, &recv.olen);
    if(ret != 0)
    {
        atclient_atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atclient_connection_send: %d\n", ret);
        goto exit;
    }

    ret = 0;

    goto exit;
exit: {
    atclient_atbytes_free(&src);
    atclient_atbytes_free(&recv);
    atclient_atstr_free(&withoutat);
    atclient_atstr_free(&url);
    atclient_atstr_free(&host);
    atclient_atstr_free(&atsigncmd);
    atclient_atstr_free(&fromcmd);
    atclient_atstr_free(&challenge);
    atclient_atstr_free(&challengewithoutdata);
    atclient_atbytes_free(&challengebytes);
    atclient_atstr_free(&pkamcmd);
    return ret;
}
}

void atclient_free(atclient *ctx)
{
    atclient_connection_free(&(ctx->root_connection));
    atclient_connection_free(&(ctx->secondary_connection));
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
