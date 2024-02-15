#include "atclient/atclient.h"
#include "atclient/atbytes.h"
#include "atclient/atkeys.h"
#include "atclient/atkeysfile.h"
#include "atclient/atsign.h"
#include "atclient/atstr.h"
#include "atclient/connection.h"
#include "atclient/stringutils.h"
#include "atlogger/atlogger.h"
#include "uuid4/uuid4.h"
#include <mbedtls/md.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define HOST_BUFFER_SIZE 1024 // the size of the buffer for the host name for root and secondary

#define TAG "atclient"

void atclient_init(atclient *ctx) { memset(ctx, 0, sizeof(atclient)); }

int atclient_start_root_connection(atclient *ctx, const char *roothost, const int rootport) {
  int ret = 1; // error by default

  atclient_connection_init(&(ctx->root_connection));

  ret = atclient_connection_connect(&(ctx->root_connection), roothost, rootport);
  if (ret != 0) {
    atclient_atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atclient_connection_connect: %d\n", ret);
    goto exit;
  }
  atclient_atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_INFO,
                        "atclient_connection_connect: %d. Successfully connected to root\n", ret);

  goto exit;

exit : { return ret; }
}

int atclient_start_secondary_connection(atclient *ctx, const char *secondaryhost, const int secondaryport) {
  int ret = 1; // error by default

  atclient_connection_init(&(ctx->secondary_connection));
  ret = atclient_connection_connect(&(ctx->secondary_connection), secondaryhost, secondaryport);
  if (ret != 0) {
    atclient_atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atclient_connection_connect: %d\n", ret);
    goto exit;
  }
  atclient_atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_INFO,
                        "atclient_connection_connect: %d. Successfully connected to secondary\n", ret);

  goto exit;

exit : { return ret; }
}

int atclient_pkam_authenticate(atclient *ctx, const atclient_atkeys atkeys, const char *atsign,
                               const unsigned long atsignlen) {
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
  if (ret != 0) {
    atclient_atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atclient_atsign_without_at_symbol: %d\n", ret);
    goto exit;
  }

  ret = atclient_atstr_set_literal(&atsigncmd, "%.*s\r\n", (int)withoutat.olen, withoutat.str);
  if (ret != 0) {
    atclient_atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atclient_atstr_set_literal: %d\n", ret);
    goto exit;
  }

  ret = atclient_atbytes_convert_atstr(&src, atsigncmd);
  if (ret != 0) {
    atclient_atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atclient_atbytes_convert_atstr: %d\n", ret);
    goto exit;
  }

  ret = atclient_connection_send(&(ctx->root_connection), src.bytes, src.olen, recv.bytes, recv.len, &(recv.olen));
  if (ret != 0) {
    atclient_atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atclient_connection_send: %d\n | failed to send: %.*s\n",
                          ret, withoutat.olen, withoutat);
    goto exit;
  }

  // 2. init secondary connection
  // recv is something like 3b419d7a-2fee-5080-9289-f0e1853abb47.swarm0002.atsign.zone:5770
  // store host and port in separate vars
  ret = atclient_atstr_set_literal(&url, "%.*s", (int)recv.olen, recv.bytes);
  if (ret != 0) {
    atclient_atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atclient_atstr_set_literal: %d\n", ret);
    goto exit;
  }

  ret = atclient_connection_get_host_and_port(&host, &port, url);
  if (ret != 0) {
    atclient_atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR,
                          "atclient_connection_get_host_and_port: %d | failed to parse url %.*s\n", ret, recv.olen,
                          recv.bytes);
    goto exit;
  }

  ret = atclient_start_secondary_connection(ctx, host.str, port);
  if (ret != 0) {
    atclient_atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atclient_start_secondary_connection: %d\n", ret);
    goto exit;
  }

  // 3. send pkam auth
  ret = atclient_atstr_set_literal(&fromcmd, "from:%.*s\r\n", (int)withoutat.olen, withoutat.str);
  if (ret != 0) {
    atclient_atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atclient_atstr_set_literal: %d\n", ret);
    goto exit;
  }

  ret = atclient_atbytes_convert(&src, fromcmd.str, fromcmd.olen);
  if (ret != 0) {
    atclient_atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atclient_atbytes_convert: %d\n", ret);
    goto exit;
  }

  ret = atclient_connection_send(&(ctx->secondary_connection), src.bytes, src.olen, recv.bytes, recv.len, &(recv.olen));
  if (ret != 0) {
    atclient_atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atclient_connection_send: %d\n", ret);
    goto exit;
  }

  ret = atclient_atstr_set_literal(&challenge, "%.*s", (int)recv.olen, recv.bytes);
  if (ret != 0) {
    atclient_atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atclient_atstr_set_literal: %d\n", ret);
    goto exit;
  }

  // remove "data:" prefix
  ret = atclient_atstr_substring(&challengewithoutdata, challenge, 5, challenge.olen);
  if (ret != 0) {
    atclient_atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR,
                          "atclient_atstr_substring: %d\n | failed to remove \'data:\' prefix", ret);
    goto exit;
  }

  // sign
  atclient_atbytes_reset(&recv);
  ret = atclient_atbytes_convert_atstr(&challengebytes, challengewithoutdata);
  if (ret != 0) {
    atclient_atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atclient_atbytes_convert_atstr: %d\n", ret);
    goto exit;
  }
  ret = atchops_rsa_sign(atkeys.pkamprivatekey, MBEDTLS_MD_SHA256, challengebytes.bytes, challengebytes.olen,
                         recv.bytes, recv.len, &recv.olen);
  if (ret != 0) {
    atclient_atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atchops_rsa_sign: %d\n", ret);
    goto exit;
  }

  ret = atclient_atstr_set_literal(&pkamcmd, "pkam:%.*s\r\n", (int)recv.olen, recv.bytes);
  if (ret != 0) {
    atclient_atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atclient_atstr_set_literal: %d\n", ret);
    goto exit;
  }

  atclient_atbytes_reset(&recv);
  ret = atclient_atbytes_convert_atstr(&src, pkamcmd);
  if (ret != 0) {
    atclient_atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atclient_atbytes_convert_atstr: %d\n", ret);
    goto exit;
  }

  ret = atclient_connection_send(&(ctx->secondary_connection), src.bytes, src.olen, recv.bytes, recv.len, &recv.olen);
  if (ret != 0) {
    atclient_atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atclient_connection_send: %d\n", ret);
    goto exit;
  }

  ret = 0;

  goto exit;
exit : {
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

void atclient_free(atclient *ctx) {
  atclient_connection_free(&(ctx->root_connection));
  atclient_connection_free(&(ctx->secondary_connection));
}

int atclient_get_encryption_key_shared_by_me(atclient *ctx, const atclient_atsign *recipient,
                                             char *enc_key_shared_by_me) {
  int ret = 1;

  // llookup:shared_key.recipient_atsign@myatsign
  char *command_prefix = "llookup:shared_key.";
  short command_prefix_len = 19;
  short atsign_with_at_len = (short)strlen(ctx->atsign.atsign);

  short command_len = command_prefix_len + (atsign_with_at_len * 2 - 1) + 3;
  char command[command_len];
  snprintf(command, command_len, "llookup:shared_key.%s%s\r\n", recipient->without_prefix_str, ctx->atsign.atsign);

  const unsigned long recvlen = 1024;
  unsigned char recv[sizeof(unsigned char) * recvlen];
  memset(recv, 0, sizeof(unsigned char) * recvlen);
  unsigned long olen = 0;

  ret = atclient_connection_send(&(ctx->secondary_connection), command, strlen((char *)command), recv, recvlen, &olen);
  if (ret != 0) {
    return ret;
  }

  char *response = recv;

  // Truncate response: "@" + myatsign + "@"
  int response_prefix_len = atsign_with_at_len + 2;
  char response_prefix[response_prefix_len];
  snprintf(response_prefix, response_prefix_len, "@%s@", ctx->atsign.without_prefix_str);

  if (atclient_stringutils_starts_with(response, recvlen, response_prefix, response_prefix_len)) {
    response = response + response_prefix_len;
  }

  if (atclient_stringutils_ends_with(response, recvlen, response_prefix, response_prefix_len)) {
    response[strlen(response) - response_prefix_len - 1] = '\0';
  }

  // does my atSign already have the recipient's shared key?
  if (atclient_stringutils_starts_with(response, recvlen, "data:", 5)) {
    response = response + 5;

    // 44 + 1
    unsigned long plaintextlen = 45;
    unsigned char plaintext[sizeof(unsigned char) * plaintextlen];
    memset(plaintext, 0, plaintextlen);
    unsigned long plaintextolen = 0;

    ret = atchops_rsa_decrypt(ctx->atkeys.encryptprivatekey, (const unsigned char *)response, strlen((char *)response),
                              plaintext, plaintextlen, &plaintextolen);
    if (ret != 0) {
      atclient_atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atchops_rsa_decrypt: %d\n", ret);
      return ret;
    }

    memcpy(enc_key_shared_by_me, plaintext, plaintextlen);
  }

  else if (atclient_stringutils_starts_with(recv, recvlen, "error:AT0015-key not found",
                                            strlen("error:AT0015-key not found"))) {
    // TODO: or do I need to create, store and share a new shared key?
  }
  return 0;
}

int atclient_get_encryption_key_shared_by_other(atclient *ctx, const atclient_atsign *recipient,
                                                char *enc_key_shared_by_other) {
  int ret = 1;

  // llookup:cached:@myatsign:shared_key@recipient_atsign
  // lookup:shared_key@recipient_atsign
  char *command_prefix = "lookup:shared_key@";
  short command_prefix_len = 18;

  short command_len = command_prefix_len + strlen(recipient->without_prefix_str) + 3;
  char command[command_len];
  snprintf(command, command_len, "lookup:shared_key@%s\r\n", recipient->without_prefix_str);

  const unsigned long recvlen = 1024;
  unsigned char recv[sizeof(unsigned char) * recvlen];
  memset(recv, 0, sizeof(unsigned char) * recvlen);
  unsigned long olen = 0;

  ret = atclient_connection_send(&(ctx->secondary_connection), command, strlen((char *)command), recv, recvlen, &olen);
  if (ret != 0) {
    return ret;
  }

  char *response = recv;

  // Truncate response: "@" + myatsign + "@"
  short response_prefix_len = (short)strlen(ctx->atsign.without_prefix_str) + 3;
  char response_prefix[response_prefix_len];
  snprintf(response_prefix, response_prefix_len, "@%s@", ctx->atsign.without_prefix_str);

  if (atclient_stringutils_starts_with(response, recvlen, response_prefix, response_prefix_len)) {
    response = response + response_prefix_len;
  }

  if (atclient_stringutils_ends_with(response, recvlen, response_prefix, response_prefix_len)) {
    response[strlen(response) - response_prefix_len - 1] = '\0';
  }

  // does my atSign already have the recipient's shared key?
  if (atclient_stringutils_starts_with(response, recvlen, "data:", 5)) {

    response = response + 5;

    // 44 + 1
    unsigned long plaintextlen = 45;
    unsigned char plaintext[sizeof(unsigned char) * plaintextlen];
    memset(plaintext, 0, plaintextlen);
    unsigned long plaintextolen = 0;

    ret = atchops_rsa_decrypt(ctx->atkeys.encryptprivatekey, (const unsigned char *)response, strlen((char *)response),
                              plaintext, plaintextlen, &plaintextolen);
    if (ret != 0) {
      atclient_atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atchops_rsa_decrypt: %d\n", ret);
      return ret;
    }
    memcpy(enc_key_shared_by_other, plaintext, plaintextlen);
  } else if (atclient_stringutils_starts_with(recv, recvlen, "error:AT0015-key not found",
                                              strlen("error:AT0015-key not found"))) {
    // There is nothing we can do, except wait for the recipient to share a new key
    ret = 1;
    return ret;
  }
  return 0;
}
