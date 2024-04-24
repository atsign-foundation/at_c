#include "atclient/atclient.h"
#include "atchops/aes.h"
#include "atchops/aesctr.h"
#include "atchops/base64.h"
#include "atchops/iv.h"
#include "atchops/rsa.h"
#include "atclient/atbytes.h"
#include "atclient/atkey.h"
#include "atclient/atkeys.h"
#include "atclient/atsign.h"
#include "atclient/atstr.h"
#include "atclient/connection.h"
#include "atclient/constants.h"
#include "atclient/stringutils.h"
#include "atlogger/atlogger.h"
#include <cJSON.h>
#include <mbedtls/md.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define HOST_BUFFER_SIZE 1024 // the size of the buffer for the host name for root and secondary

#define TAG "atclient"

void atclient_init(atclient *ctx) { memset(ctx, 0, sizeof(atclient)); }

int atclient_start_client_connection(atclient *ctx, const char *secondaryhost, const int secondaryport) {
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

exit: { return ret; }
}

int atclient_pkam_authenticate(atclient *ctx, atclient_connection *root_conn, const atclient_atkeys atkeys,
                               const char *atsign, const size_t atsignlen) {
  int ret = 1; // error by default

  // 1. init root connection
  const size_t srclen = 1024;
  atclient_atbytes src;
  atclient_atbytes_init(&src, srclen);

  const size_t recvlen = 1024;
  atclient_atbytes recv;
  atclient_atbytes_init(&recv, recvlen);

  const size_t withoutatlen = 1024;
  atclient_atstr withoutat;
  atclient_atstr_init(&withoutat, withoutatlen);

  const size_t urllen = 256;
  atclient_atstr url;
  atclient_atstr_init(&url, 256);

  atclient_atstr host;
  atclient_atstr_init(&host, 256);
  int port = 0;

  const size_t atsigncmdlen = 1024;
  atclient_atstr atsigncmd;
  atclient_atstr_init(&atsigncmd, atsigncmdlen);

  const size_t fromcmdlen = 1024;
  atclient_atstr fromcmd;
  atclient_atstr_init(&fromcmd, fromcmdlen);

  const size_t challengelen = 1024;
  atclient_atstr challenge;
  atclient_atstr_init(&challenge, challengelen);

  const size_t challengewithoutdatalen = 1024;
  atclient_atstr challengewithoutdata;
  atclient_atstr_init(&challengewithoutdata, challengewithoutdatalen);

  const size_t challengebyteslen = 1024;
  atclient_atbytes challengebytes;
  atclient_atbytes_init(&challengebytes, challengebyteslen);

  const size_t pkamcmdlen = 1024;
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

  ret = atclient_connection_send(root_conn, src.bytes, src.olen, recv.bytes, recv.len, &(recv.olen));
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

  ret = atclient_start_client_connection(ctx, host.str, port);
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

  // check for data:success
  if (!atclient_stringutils_starts_with((char *)recv.bytes, recv.olen, "data:success", strlen("data:success"))) {
    ret = 1;
    atclient_atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR,
                          "recv was \"%.*s\" and did not have prefix \"data:success\"\n", (int)recv.olen, recv.bytes);
    goto exit;
  }

  // initialize ctx->atsign.atsign and ctx->atsign.withour_prefix_str to the newly authenticated atSign
  ret = atclient_atsign_init(&(ctx->atsign), atsign);
  if (ret != 0) {
    atclient_atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atclient_atsign_init: %d\n", ret);
    goto exit;
  }

  // set atkeys
  ctx->atkeys = atkeys;

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

void atclient_free(atclient *ctx) { atclient_connection_free(&(ctx->secondary_connection)); }
