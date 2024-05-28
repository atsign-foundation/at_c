#include "atclient/atclient.h"
#include "atchops/base64.h"
#include "atchops/rsa.h"
#include "atclient/atbytes.h"
#include "atclient/atkeys.h"
#include "atclient/atsign.h"
#include "atclient/atstr.h"
#include "atclient/connection.h"
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

static int atclient_start_atserver_connection(atclient *ctx, const char *secondaryhost, const int secondaryport);

void atclient_init(atclient *ctx) {
  memset(ctx, 0, sizeof(atclient));
  ctx->async_read = false;
  ctx->atserver_connection_started = false;
}

void atclient_free(atclient *ctx) {
  // TODO: add initialized fields to free

  if (ctx->atserver_connection_started) {
    atclient_connection_free(&(ctx->atserver_connection));
  }

  // TODO: free atsign if it's been initialized (called atclient_atsign_init)
  // TODO: free atkeys if it's been initialized (called atclient_atkeys_init)
}

int atclient_pkam_authenticate(atclient *ctx, const char *atserver_host, const int atserver_port,
                               const atclient_atkeys *atkeys, const char *atsign) {
  int ret = 1; // error by default

  char *rootcmd = NULL;
  char *fromcmd = NULL;
  char *pkamcmd = NULL;
  char *atsign_with_at_symbol = NULL;

  const size_t recvsize = 1024;
  unsigned char recv[recvsize];
  memset(recv, 0, sizeof(unsigned char) * recvsize);
  size_t recvlen;

  const size_t challengesize = 256;
  char challenge[challengesize];
  memset(challenge, 0, sizeof(char) * challengesize);
  size_t challengelen = 0;

  const size_t signaturesize = 256;
  unsigned char signature[signaturesize];
  memset(signature, 0, sizeof(unsigned char) * signaturesize);

  const size_t signaturebase64size = 2048;
  unsigned char signaturebase64[signaturebase64size];
  memset(signaturebase64, 0, sizeof(unsigned char) * signaturebase64size);
  size_t signaturebase64len = 0;

  if (ctx == NULL) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "ctx is NULL\n");
    goto exit;
  }

  if ((ret = atclient_stringutils_atsign_with_at_symbol(atsign, strlen(atsign), &(atsign_with_at_symbol))) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atclient_stringutils_atsign_with_at_symbol: %d\n", ret);
    goto exit;
  }

  const char *atsign_without_at_str = (atsign_with_at_symbol + 1);

  // log atsign_without_prefix_str
  // log atserver_host and port
  atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_INFO, "atsign_without_prefix_str: %s\n", atsign_without_at_str);
  atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_INFO, "atserver_host: %s\n", atserver_host);
  atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_INFO, "atserver_port: %d\n", atserver_port);

  if ((ret = atclient_start_atserver_connection(ctx, atserver_host, atserver_port)) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atclient_start_atserver_connection: %d\n", ret);
    goto exit;
  }

  const size_t fromcmdsize =
      strlen("from:") + strlen(atsign_without_at_str) + strlen("\r\n") + 1; // "from:" has a length of 5
  fromcmd = malloc(sizeof(char) * fromcmdsize);
  if (fromcmd == NULL) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "Failed to allocate memory for fromcmd\n");
    goto exit;
  }
  snprintf(fromcmd, fromcmdsize, "from:%s\r\n", atsign_without_at_str);

  if ((ret = atclient_connection_send(&(ctx->atserver_connection), (unsigned char *)fromcmd, fromcmdsize - 1, recv,
                                      recvsize, &recvlen)) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atclient_connection_send: %d\n", ret);
    goto exit;
  }

  memcpy(challenge, recv, recvlen);
  // remove data:
  memmove(challenge, challenge + 5, recvlen - 5);
  challengelen = recvlen - 5;

  // sign
  if ((ret = atchops_rsa_sign(atkeys->pkamprivatekey, ATCHOPS_MD_SHA256, (unsigned char *)challenge, challengelen,
                              signature)) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atchops_rsa_sign: %d\n", ret);
    goto exit;
  }

  if ((ret = atchops_base64_encode(signature, signaturesize, signaturebase64, signaturebase64size,
                                   &signaturebase64len)) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atchops_base64_encode: %d\n", ret);
    goto exit;
  }

  const size_t pkamcmdsize = strlen("pkam:") + signaturebase64len + strlen("\r\n") + 1;
  pkamcmd = malloc(sizeof(char) * pkamcmdsize);
  if (pkamcmd == NULL) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "Failed to allocate memory for pkamcmd\n");
    goto exit;
  }
  snprintf(pkamcmd, pkamcmdsize, "pkam:%s\r\n", signaturebase64);
  memset(recv, 0, sizeof(unsigned char) * recvsize);
  if ((ret = atclient_connection_send(&(ctx->atserver_connection), (unsigned char *)pkamcmd, pkamcmdsize - 1, recv,
                                      recvsize, &recvlen)) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atclient_connection_send: %d\n", ret);
    goto exit;
  }

  // check for data:success
  if (!atclient_stringutils_starts_with((char *)recv, recvlen, "data:success", strlen("data:success"))) {
    ret = 1;
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "recv was \"%.*s\" and did not have prefix \"data:success\"\n",
                 (int)recvlen, recv);
    goto exit;
  }

  // initialize ctx->atsign.atsign and ctx->atsign.withour_prefix_str to the newly authenticated atSign
  if ((ret = atclient_atsign_init(&(ctx->atsign), atsign) != 0)) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atclient_atsign_init: %d\n", ret);
    goto exit;
  }

  // set atkeys
  ctx->atkeys = *atkeys;

  ret = 0;

  goto exit;
exit: {
  free(rootcmd);
  free(fromcmd);
  free(pkamcmd);
  return ret;
}
}

int atclient_send_heartbeat(atclient *heartbeat_conn) {
  int ret = -1;

  unsigned char *recv = NULL;

  const char *command = "noop:0\r\n";
  const size_t commandlen = strlen(command);

  const size_t recvsize = 64;
  if (!heartbeat_conn->async_read) {
    recv = malloc(sizeof(unsigned char) * recvsize);
    memset(recv, 0, sizeof(unsigned char) * recvsize);
  }
  size_t recvlen = 0;
  char *ptr = (char *)recv;

  ret = atclient_connection_send(&heartbeat_conn->atserver_connection, (unsigned char *)command, commandlen, recv,
                                 recvsize, &recvlen);
  if (ret != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "Failed to send noop command: %d\n", ret);
    goto exit;
  } else if (heartbeat_conn->async_read) {
    goto exit;
  }

  if (!atclient_stringutils_starts_with((const char *)ptr, recvlen, "data:ok", strlen("data:ok")) &&
      !atclient_stringutils_ends_with((const char *)ptr, recvlen, "data:ok", strlen("data:ok"))) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "Failed to receive heartbeat response\n");
    ret = -1;
    goto exit;
  }

  ret = 0;
  goto exit;

exit: {
  if (!heartbeat_conn->async_read) {
    free(recv);
  }
  return ret;
}
}

void atclient_set_read_timeout(atclient *ctx, int timeout_ms) {
  mbedtls_ssl_conf_read_timeout(&(ctx->atserver_connection.ssl_config), timeout_ms);
}

static int atclient_start_atserver_connection(atclient *ctx, const char *secondaryhost, const int secondaryport) {
  int ret = 1; // error by default

  atclient_connection_init(&(ctx->atserver_connection), ATCLIENT_CONNECTION_TYPE_ATSERVER);

  if ((ret = atclient_connection_connect(&(ctx->atserver_connection), secondaryhost, secondaryport)) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atclient_connection_connect: %d\n", ret);
    goto exit;
  }

  ctx->atserver_connection_started = true;

  goto exit;

exit: { return ret; }
}

int atclient_find_atserver_address(const char *atdirectory_host, const int atdirectory_port, const char *atsign,
                                   char **atserver_host, int *atserver_port) {
  int ret = 1;

  atclient_connection atdirectory_conn;
  atclient_connection_init(&atdirectory_conn, ATCLIENT_CONNECTION_TYPE_ATDIRECTORY);

  const size_t recvsize = 1024;
  unsigned char recv[recvsize];
  memset(recv, 0, sizeof(unsigned char) * recvsize);
  size_t recvlen = 0;

  char *atsign_without_at_symbol = NULL;
  char *cmd = NULL;

  if ((ret = atclient_connection_connect(&atdirectory_conn, atdirectory_host, atdirectory_port)) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atclient_connection_connect: %d\n", ret);
    goto exit;
  }

  if ((ret = atclient_stringutils_atsign_without_at_symbol(atsign, strlen(atsign), &atsign_without_at_symbol)) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atclient_stringutils_atsign_without_at_symbol: %d\n", ret);
    goto exit;
  }

  size_t cmdsize = (strlen(atsign_without_at_symbol)) + strlen("\n") + 1;
  cmd = malloc(sizeof(char) * cmdsize);
  if (cmd == NULL) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "Failed to allocate memory for cmd\n");
    goto exit;
  }
  snprintf(cmd, cmdsize, "%s\n", atsign_without_at_symbol);

  if ((ret = atclient_connection_send(&atdirectory_conn, (unsigned char *)cmd, cmdsize - 1, recv, recvsize,
                                      &recvlen)) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atclient_connection_send: %d\n", ret);
    goto exit;
  }

  if (recvlen == 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "No data received from atdirectory\n");
    goto exit;
  }

  // recv has something like `228aafb0-94d3-5aa2-a3b3-e36af115480d.swarm0002.atsign.zone:6943`
  // we need to split it into host and port
  char *host = strtok((char *)recv, ":");
  char *portstr = strtok(NULL, ":");
  if (portstr == NULL) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "Failed to parse port from atdirectory response\n");
    goto exit;
  }

  *atserver_host = strdup(host);
  *atserver_port = atoi(portstr);

  ret = 0;
  goto exit;
exit: {
  free(atsign_without_at_symbol);
  free(cmd);
  atclient_connection_free(&atdirectory_conn);
  return ret;
}
}