#include "atclient/atclient.h"
#include "atchops/aes.h"
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

int atclient_start_secondary_connection(atclient *ctx, const char *secondaryhost, const int secondaryport) {
  int ret = 1; // error by default

  atclient_connection_init(&(ctx->secondary_connection));

  ret = atclient_connection_connect(&(ctx->secondary_connection), secondaryhost, secondaryport);
  if (ret != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atclient_connection_connect: %d\n", ret);
    goto exit;
  }
  atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_INFO,
                        "atclient_connection_connect: %d. Successfully connected to secondary\n", ret);

  goto exit;

exit : { return ret; }
}

int atclient_pkam_authenticate(atclient *ctx, atclient_connection *root_conn, const atclient_atkeys *atkeys,
                               const char *atsign) {
  int ret = 1; // error by default

  char *atsign_without_prefix_str = atsign + 1;

  char *root_command = NULL;
  char *from_command = NULL;
  char *pkam_command = NULL;

  // 1. init root connection

  const size_t recvlen = 1024;
  atclient_atbytes recv;
  atclient_atbytes_init(&recv, recvlen);

  const size_t urllen = 256;
  atclient_atstr url;
  atclient_atstr_init(&url, 256);

  atclient_atstr host;
  atclient_atstr_init(&host, 256);
  int port = 0;

  const size_t challengelen = 1024;
  atclient_atstr challenge;
  atclient_atstr_init(&challenge, challengelen);

  const size_t challengebyteslen = 1024;
  atclient_atbytes challengebytes;
  atclient_atbytes_init(&challengebytes, challengebyteslen);

  const size_t challengewithoutdatalen = 1024;
  atclient_atstr challengewithoutdata;
  atclient_atstr_init(&challengewithoutdata, challengewithoutdatalen);

  const size_t signaturebase64size = 1024; // encoded signature should surely be less than 256 bytes
  unsigned char signaturebase64[signaturebase64size];
  memset(signaturebase64, 0, sizeof(unsigned char) * signaturebase64size);
  size_t signaturebase64len = 0;

  // build command, ie atsign without "@"
  const short root_command_len = strlen(atsign_without_prefix_str) + 3;
  root_command = calloc(root_command_len, sizeof(char));
  snprintf(root_command, root_command_len, "%s\r\n", atsign_without_prefix_str);

  ret = atclient_connection_send(root_conn, (unsigned char *)root_command, root_command_len - 1, recv.bytes, recv.len,
                                 &(recv.olen));
  if (ret != 0) {
    atclient_atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atclient_connection_send: %d\n | failed to send: %.*s\n",
                          ret, root_command_len, root_command);
    goto exit;
  }

  // 2. init secondary connection
  // recv is something like 3b419d7a-2fee-5080-9289-f0e1853abb47.swarm0002.atsign.zone:5770
  // store host and port in separate vars
  ret = atclient_atstr_set_literal(&url, "%.*s", (int)recv.olen, recv.bytes);
  if (ret != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atclient_atstr_set_literal: %d\n", ret);
    goto exit;
  }

  ret = atclient_connection_get_host_and_port(&host, &port, url);
  if (ret != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR,
                          "atclient_connection_get_host_and_port: %d | failed to parse url %.*s\n", ret, recv.olen,
                          recv.bytes);
    goto exit;
  }

  ret = atclient_start_secondary_connection(ctx, host.str, port);
  if (ret != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atclient_start_secondary_connection: %d\n", ret);
    goto exit;
  }

  // 3. send pkam auth

  // build command, ie "from:atsign"
  const short from_command_len = 5 + root_command_len; // "from:" has a length of 5
  from_command = calloc(from_command_len, sizeof(char));
  snprintf(from_command, from_command_len, "from:%s", root_command);

  ret = atclient_connection_send(&(ctx->secondary_connection), (unsigned char *)from_command, from_command_len - 1,
                                 recv.bytes, recv.len, &(recv.olen));
  if (ret != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atclient_connection_send: %d\n", ret);
    goto exit;
  }

  free(root_command);
  root_command = NULL;
  free(from_command);
  from_command = NULL;

  ret = atclient_atstr_set_literal(&challenge, "%.*s", (int)recv.olen, recv.bytes);
  if (ret != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atclient_atstr_set_literal: %d\n", ret);
    goto exit;
  }

  // remove "data:" prefix
  ret = atclient_atstr_substring(&challengewithoutdata, challenge, 5, challenge.olen);
  if (ret != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR,
                          "atclient_atstr_substring: %d\n | failed to remove \'data:\' prefix", ret);
    goto exit;
  }

  // sign
  ret = atclient_atbytes_convert(&challengebytes, challengewithoutdata.str, challengewithoutdata.olen);
  if (ret != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atclient_atstr_to_atbytes: %d\n", ret);
    goto exit;
  }

  atclient_atbytes_reset(&recv);
  ret = atchops_rsa_sign(atkeys->pkamprivatekey, MBEDTLS_MD_SHA256, challengebytes.bytes, strlen(challengebytes.bytes),
                         recv.bytes);
  if (ret != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atchops_rsa_sign: %d\n", ret);
    goto exit;
  }
  // log recv.bytes
  recv.olen = 256;

  ret = atchops_base64_encode(recv.bytes, recv.olen, signaturebase64, signaturebase64size, &signaturebase64len);
  if (ret != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atchops_base64_encode: %d\n", ret);
    goto exit;
  }

  const short pkam_command_len = 5 + (int) signaturebase64len + 3;
  pkam_command = calloc(pkam_command_len, sizeof(char));
  snprintf(pkam_command, pkam_command_len, "pkam:%s\r\n", signaturebase64);
  atclient_atbytes_reset(&recv);

  ret = atclient_connection_send(&(ctx->secondary_connection), pkam_command, pkam_command_len - 1, recv.bytes, recv.len,
                                 &recv.olen);
  if (ret != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atclient_connection_send: %d\n", ret);
    goto exit;
  }

  free(pkam_command);
  pkam_command = NULL;

  // check for data:success
  if (!atclient_stringutils_starts_with((char *)recv.bytes, recv.olen, "data:success", 12)) {
    ret = 1;
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR,
                          "recv was \"%.*s\" and did not have prefix \"data:success\"\n", (int)recv.olen, recv.bytes);
    goto exit;
  }

  // initialize ctx->atsign.atsign and ctx->atsign.withour_prefix_str to the newly authenticated atSign
  ret = atclient_atsign_init(&(ctx->atsign), atsign);
  if (ret != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atclient_atsign_init: %d\n", ret);
    goto exit;
  }

  // set atkeys
  ctx->atkeys = *atkeys;

  ret = 0;

  goto exit;
exit : {
  free(root_command);
  free(from_command);
  free(pkam_command);
  atclient_atbytes_free(&recv);
  atclient_atstr_free(&url);
  atclient_atstr_free(&host);
  atclient_atstr_free(&challenge);
  atclient_atbytes_free(&challengebytes);
  return ret;
}
}

void atclient_free(atclient *ctx) { atclient_connection_free(&(ctx->secondary_connection)); }
