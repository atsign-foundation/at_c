#ifndef ATCLIENT_H
#define ATCLIENT_H

#include "atclient/atkeys.h"
#include "atclient/atsign.h"
#include "atclient/connection.h"

/**
 * @brief represents atclient
 *
 */
typedef struct atclient {
  atclient_connection root_connection;
  atclient_connection secondary_connection;
  atclient_atsign atsign;
  atclient_atkeys atkeys;
} atclient;

/**
 * @brief initialize the atclient context for further use
 *
 * @param ctx pointer to the atclient context to initialize
 */
void atclient_init(atclient *ctx);

/**
 * @brief initalize the atclient's root connection to the specified host and port
 *
 * @param ctx initialized atclient context
 * @param roothost host of root (e.g. root.atsign.org)
 * @param rootport  port of the root (e.g. 64)
 * @return int 0 on success, error otherwise
 */
int atclient_start_root_connection(atclient *ctx, const char *roothost, const int rootport);

/**
 * @brief initialize the atclient's secondary connection to the specified host and port
 *
 * @param ctx initialized atclient context
 * @param secondaryhost host of secondary. this is usually fetched from the root connection
 * @param secondaryport port of secondary. this is usually fetched from the root connection
 * @return int 0 on success, error otherwise
 */
int atclient_start_secondary_connection(atclient *ctx, const char *secondaryhost, const int secondaryport);

/**
 * @brief authenticate with secondary server with RSA pkam private key. it is expected atkeys has been populated with
 * the pkam private key and atclient context is connected to the root server
 *
 * @param ctx initialized atclient context
 * @param atkeys populated atkeys, especially with the pkam private key
 * @param atsign the atsign the atkeys belong to
 * @return int 0 on success
 */
int atclient_pkam_authenticate(atclient *ctx, const atclient_atkeys atkeys, const char *atsign,
                               const unsigned long atsignlen);
int atclient_put(atclient *ctx, const char *key, const char *value);
int atclient_get(atclient *ctx, const char *key, char *value, const unsigned long valuelen);
int atclient_delete(atclient *ctx, const char *key);
void atclient_free(atclient *ctx);

/**
 * @brief Looks up the symmetric shared key which the atclient's atsign shared with the recipient's atsign.
 * If no key is found, it will create, store and share a new one with the recipient's atsign.
 *
 * @param ctx initialized atclient context (required)
 * @param recipient an atclient_atsign struct corresponding to the atsign with whom the key was shared (required)
 * @param enc_key_shared_by_me the output shared key in b64 format (required)
 * @return int 0 on success, error otherwise
 */
int atclient_get_encryption_key_shared_by_me(atclient *ctx, const atclient_atsign *recipient,
                                             char *enc_key_shared_by_me);

/**
 * @brief Looks up the symmetric shared key which the recipient's atsign shared with atclient's atsign.
 * If no key is found, the function will return an error.
 *
 * @param ctx initialized atclient context (required)
 * @param atkeys an atclient_atsign struct corresponding to the atsign who shared the key with the atclient’s atsign
 * (required)
 * @param enc_key_shared_by_other the output shared key in b64 format (required)
 * @return int 0 on success, error otherwise
 */
int atclient_get_encryption_key_shared_by_other(atclient *ctx, const atclient_atsign *recipient,
                                                char *enc_key_shared_by_other);

#endif
