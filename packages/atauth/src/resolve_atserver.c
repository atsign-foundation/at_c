#include "resolve_atserver.h"
#include <atclient/atclient_utils.h>
#include <atlogger/atlogger.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define TAG "resolve_atserver"

#define DEFAULT_ATDIRECTORY_PORT 64

#define PROXY_PREFIX "proxy:"

// The longest legal hostname is 253 characters
#define MAX_HOST_LEN 253

int atauth_resolve_atserver(const char *root_spec, const char *atsign, char **atserver_host, uint16_t *atserver_port) {
  if (root_spec == NULL || root_spec[0] == '\0' || atserver_host == NULL || atserver_port == NULL) {
    return 1;
  }

  bool via_proxy = strncmp(root_spec, PROXY_PREFIX, strlen(PROXY_PREFIX)) == 0;
  const char *hostport = via_proxy ? root_spec + strlen(PROXY_PREFIX) : root_spec;
  if (hostport[0] == '\0') {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "No host given after '%s' in root server spec\n", PROXY_PREFIX);
    return 1;
  }

  char host[MAX_HOST_LEN + 1];
  uint16_t port = DEFAULT_ATDIRECTORY_PORT;

  const char *colon = strchr(hostport, ':');
  if (colon != NULL) {
    size_t host_len = (size_t)(colon - hostport);
    if (host_len == 0 || host_len > MAX_HOST_LEN) {
      atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "Invalid host in root server spec: %s\n", root_spec);
      return 1;
    }
    memcpy(host, hostport, host_len);
    host[host_len] = '\0';
    port = (uint16_t)atoi(colon + 1);
    if (port == 0) {
      atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "Invalid port in root server spec: %s\n", root_spec);
      return 1;
    }
  } else {
    if (strlen(hostport) > MAX_HOST_LEN) {
      atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "Invalid host in root server spec: %s\n", root_spec);
      return 1;
    }
    snprintf(host, sizeof(host), "%s", hostport);
  }

  if (via_proxy) {
    // No atDirectory: every atServer connection goes to the reverse proxy
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_INFO,
                 "Connecting to the atServer via the reverse proxy %s:%u (no atDirectory lookup)\n", host,
                 (unsigned int)port);
    // malloc+copy rather than strdup: strdup is not declared under strict
    // C99 without feature test macros (breaks -Werror builds on glibc)
    size_t host_size = strlen(host) + 1;
    *atserver_host = malloc(host_size);
    if (*atserver_host == NULL) {
      return 1;
    }
    memcpy(*atserver_host, host, host_size);
    *atserver_port = port;
    return 0;
  }

  return atclient_utils_find_atserver_address(host, port, atsign, atserver_host, atserver_port);
}
