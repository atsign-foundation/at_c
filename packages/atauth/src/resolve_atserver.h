#ifndef ATAUTH_RESOLVE_ATSERVER_H
#define ATAUTH_RESOLVE_ATSERVER_H

#include <stdint.h>

/**
 * @brief Resolve the atServer address for an atsign from a root server spec,
 * following the same convention as the Dart AtRootDomain / at_lookup:
 *
 *   host             -> ask the atDirectory at host:64
 *   host:port        -> ask the atDirectory at host:port
 *   proxy:host       -> no atDirectory: the atServer address is host:64
 *   proxy:host:port  -> no atDirectory: the atServer address is host:port
 *
 * The 'proxy:' forms support environments where only port 443 egress is
 * allowed and atServer connections go via a reverse proxy, e.g.
 * 'proxy:proxy0001.atsign.org:443'.
 *
 * @param root_spec the root server spec (e.g. the --rootServer/-r value)
 * @param atsign the atsign whose atServer address is wanted
 * @param atserver_host output host, malloc'd, caller frees
 * @param atserver_port output port
 * @return int 0 on success
 */
int atauth_resolve_atserver(const char *root_spec, const char *atsign, char **atserver_host, uint16_t *atserver_port);

#endif
