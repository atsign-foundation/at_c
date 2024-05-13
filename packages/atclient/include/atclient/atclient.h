#ifndef ATCLIENT_H
#define ATCLIENT_H

#include "atclient/atkey.h"
#include "atclient/atkeys.h"
#include "atclient/atsign.h"
#include "atclient/connection.h"
#include <stdbool.h>
#include <stddef.h>

/**
 * @brief represents atclient
 *
 */
typedef struct atclient {
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
 * @param root_conn initialized root connection
 * @param atkeys populated atkeys, especially with the pkam private key
 * @param atsign the atsign the atkeys belong to
 * @return int 0 on success
 */
int atclient_pkam_authenticate(atclient *ctx, atclient_connection *root_conn, const atclient_atkeys *atkeys,
                               const char *atsign);

/**
 * @brief Put a string value into your atServer.
 * `atclient` must satisfy two conditions before calling this function:
 * 1. initialized with atclient_init()
 * 2. authenticated via atclient_pkam_authenticate()
 *
 * `atkey` must satisfy the following condition before calling this function:
 * 1. initialized with atclient_atkey_init()
 * 2. have populated values (such as a name, sharedby, sharedwith, etc,.) depending on what kind of atkey you want
 * to be associated with your value.
 *
 * @param atclient the atclient context (must satisfy the two conditions stated above)
 * @param atkey the populated atkey to put the value into (must satisfy the two conditions stated above)
 * @param value the value to put into atServer
 * @param valuelen the length of the value (most of the time you will use strlen() on a null-terminated string for
 * this value)
 * @param commitid (optional) the output commitid of the put operation that the atServer returns
 * @return int 0 on success
 */
int atclient_put(atclient *atclient, atclient_atkey *atkey, const char *value, const size_t valuelen, int *commitid);

// TODO: add put self which doesn't need the root_conn OR allow root_conn to be null if the key is a self key

/**
 * @brief Get a string value from your atServer.
 * `atclient` must satisfy two conditions before calling this function:
 * 1. initialized with atclient_init()
 * 2. authenticated via atclient_pkam_authenticate()
 *
 * `atkey` must satisfy the following condition before calling this function:
 * 1. initialized with atclient_atkey_init()
 * 2. have populated values (such as a name, sharedby, sharedwith, etc,.) depending on what kind of atkey you want to be
 * associated with your value.
 *
 * @param atclient the atclient context (must satisfy the two conditions stated above)
 * @param atkey the populated atkey to get the value from (must satisfy the two conditions stated above)
 * @param value the buffer to hold value gotten from atServer
 * @param valuesize the buffer length allocated for the value
 * @param valuelen the output length of the value gotten from atServer
 * @return int 0 on success
 */
int atclient_get_selfkey(atclient *atclient, atclient_atkey *atkey, char *value, const size_t valuesize,
                         size_t *valuelen);

/**
 * @brief Get a publickey from your atServer or another atServer
 * `atclient` must satisfy two conditions before calling this function:
 * 1. initialized with atclient_init()
 * 2. authenticated via atclient_pkam_authenticate()
 *
 * `atkey` must satisfy the following condition before calling this function:
 * 1. initialized with atclient_atkey_init()
 * 2. have populated values (such as a name, sharedby, sharedwith, etc,.) depending on what kind of atkey you want to be
 * associated with your value.
 *
 * @param atclient the atclient context (must satisfy the two conditions stated above)
 * @param atkey the populated atkey to get the value from (must satisfy the two conditions stated above)
 * @param value the buffer to hold value gotten from atServer
 * @param valuesize the buffer length allocated for the value
 * @param valuelen the output length of the value gotten from atServer
 * @param bypasscache true if you want to bypass the cached publickey, that might be on your atServer, and get the most
 * up-to-date value straight from the atServer that the publickey sits on, false otherwise
 * @return int 0 on success
 */
int atclient_get_publickey(atclient *atclient, atclient_atkey *atkey, char *value, const size_t valuesize,
                           size_t *valuelen, bool bypasscache);

/**
 * @brief Get a sharedkey either shared by you or shared with you and receive the decrypted plaintext value.
 * `atclient` must satisfy two conditions before calling this function:
 * 1. initialized with atclient_init()
 * 2. authenticated via atclient_pkam_authenticate()
 *
 * `atkey` must satisfy the following condition before calling this function:
 * 1. initialized with atclient_atkey_init()
 * 2. have populated values (such as a name, sharedby, sharedwith, etc,.) depending on what kind of atkey you want to be
 * associated with your value.
 *
 * @param atclient The atclient context (must satisfy the two conditions stated above)
 * @param root_conn initialized root connection
 * @param atkey The populated atkey to get the value from (must satisfy the two conditions stated above)
 * @param value The buffer to hold value gotten from atServer
 * @param valuesize The buffer length allocated for the value
 * @param valuelen The output length of the value gotten from atServer
 * @param shared_enc_key The correct shared encryption key (get_encryption_key_shared_by_me or
 * get_encryption_key_shared_by_other, depending on the case). If NULL is provided, the method will check
 * create_new_encryption_key_shared_by_me_if_not_found parameter.
 * @param create_new_encryption_key_shared_by_me_if_not_found If NULL is provided for the shared_enc_key parameter, the
 * function will attempt to retrieve it from the at_server. This parameter can be used to determine whether the key
 * should be created (if it hasn’t already been) or not.
 * @return int 0 on success
 */
int atclient_get_sharedkey(atclient *atclient, atclient_atkey *atkey, char *value, const size_t valuesize,
                           size_t *valuelen, char *shared_enc_key,
                           const bool create_new_encryption_key_shared_by_me_if_not_found);

/**
 * @brief Delete an atkey from your atserver
 * `atclient` must satisfy two conditions before calling this function:
 * 1. initialized with atclient_init()
 * 2. authenticated via atclient_pkam_authenticate()
 *
 * `atkey` must satisfy the following condition before calling this function:
 * 1. initialized with atclient_atkey_init()
 * 2. have populated values (such as a name, sharedby, sharedwith, etc,.) depending on what kind of atkey you want to be
 * associated with your value.
 *
 * @param atclient the atclient context (must satisfy the two conditions stated above)
 * @param atkey the populated atkey to delete from atServer (must satisfy the two conditions stated above)
 * @return int 0 on success
 */
int atclient_delete(atclient *atclient, const atclient_atkey *atkey);

/**
 * @brief Send a heartbeat (noop)
 * @param heartbeat_conn the initialized and pkam authenticated atclient context to send the heartbeat
 * @param listen_for_ack if true, the function will wait for an ack from the server, if false, it will not. Set to false
 * if you want a more lightweight heartbeat
 * @return 0 on success, non-zero on error
 *
 * @note Ideally this is scheduled to be sent every 30 seconds
 * @note this is different than a normal noop command, since we don't listen for the response from the server
 * @note It is the responsibility of the caller to ensure that the connection is still alive
 */
int atclient_send_heartbeat(atclient *heartbeat_conn, bool listen_for_ack);

/**
 * @brief Frees memory allocated by atclient's _init function. The caller of _init is responsible for calling this once
 * it is done with the atclient context.
 *
 * @param ctx the atclient context to free
 */
void atclient_free(atclient *ctx);

#endif
