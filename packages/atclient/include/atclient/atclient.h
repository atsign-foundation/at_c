#ifndef ATCLIENT_ATCLIENT_H
#define ATCLIENT_ATCLIENT_H

#include "atclient/atkey.h"
#include "atclient/atkeys.h"
#include "atclient/connection.h"
#include "atclient/request_options.h"
#include <stdbool.h>
#include <stddef.h>

#define VALUE_INITIALIZED 0b00000001

#define ATCLIENT_ATSIGN_INDEX 0
#define ATCLIENT_ATSERVER_CONNECTION_INDEX 0
#define ATCLIENT_ATKEYS_INDEX 0

#define ATCLIENT_ATSIGN_INITIALIZED (VALUE_INITIALIZED << 0)
#define ATCLIENT_ATSERVER_CONNECTION_INITIALIZED (VALUE_INITIALIZED << 1)
#define ATCLIENT_ATKEYS_INITIALIZED (VALUE_INITIALIZED << 2)

/**
 * @brief represents atclient
 * TODO: more documentation
 */
typedef struct atclient {
  char *atsign;
  atclient_connection atserver_connection;
  atclient_atkeys atkeys;

  // Warning! async_read is an experimental feature and not fully implemented.
  // You should leave this set to false unless you know what you are doing.
  bool async_read;

  // used internally to track which fields are ready for use
  // bit 0 == atsign | true == allocated and populated, false == not allocated.
  // bit 1 == atserver_connection | true == connection is expected to be fully functional, false == connection was not
  // started and is expected to be non-functional.
  // bit 2 == atkeys | true == atkeys are populated with the necessary
  // keys, false == atkeys are not populated.
  uint8_t _initialized_fields[1];
} atclient;

/**
 * @brief initialize the atclient context for further use
 *
 * @param ctx pointer to the atclient context to initialize
 */
void atclient_init(atclient *ctx);

/**
 * @brief Frees memory allocated by atclient's _init function. The caller of _init is responsible for calling this once
 * it is done with the atclient context.
 *
 * @param ctx the atclient context to free
 */
void atclient_free(atclient *ctx);

/**
 * @brief returns true if the atsign is initialized and is ready for use and is allocated
 *
 * @param ctx assumed to be initialized using atclient_init
 * @return true if the atsign is initialized and is ready for use and is allocated
 * @return false if the atsign is not initialized and is not ready for use and is not allocated
 */
bool atclient_is_atsign_initialized(const atclient *ctx);

/**
 * @brief sets the atsign in the atclient context. This function will allocate memory for the atsign and copy the input
 * atsign
 *
 * @param ctx the atclient context to set the atsign in, assumed to be initialized using atclient_init and non-null
 * @param atsign the atsign to set in the atclient context, assumed to be NON-NULL
 * @return int 0 on success
 */
int atclient_set_atsign(atclient *ctx, const char *atsign);

/**
 * @brief unsets the atsign in the atclient context. This function will free the memory allocated for the atsign
 *
 * @param ctx the atclient context to unset the atsign in, assumed to be initialized using atclient_init and non-null
 */
void atclient_unset_atsign(atclient *ctx);

/**
 * @brief check if the atserver connection was started and is ready for use. This function will return true if the
 * connection is expected to be fully functional, it doesn't necessarily mean that the connection is still alive and
 * connected.
 *
 * @param ctx the atclient context, assumed to be initialized using atclient_init and non-null
 * @return true if the connection is expected to be fully functional and was started at least once
 * @return false if connection was not started and is expected to be non-functional
 */
bool atclient_is_atserver_connection_started(const atclient *ctx);

/**
 * @brief starts the atserver connection. This function will connect to the atserver host and port. This function will
 * not pkam authenticate for you
 *
 * @param ctx the atclient context, assumed to be initialized using atclient_init
 * @param secondaryhost the host of the atserver, this string is assumed to be non-null null terminated
 * @param secondaryport the port of the atserver
 * @return int
 */
int atclient_start_atserver_connection(atclient *ctx, const char *secondaryhost, const int secondaryport);

/**
 * @brief Stops the atserver connection. This function will disconnect the atserver connection.
 *
 * @param ctx assumed to be initialized using atclient_init and non-null
 */
void atclient_stop_atserver_connection(atclient *ctx);

/**
 * @brief authenticate with secondary server with RSA pkam private key. it is expected atkeys has been populated with
 * the pkam private key and atclient context is connected to the root server
 *
 * @param ctx initialized atclient context
 * @param atserver_host host of secondary. if you do not know the host, you can use
 * atclient_utils_find_atserver_address, this string is assumed to be null terminated
 * @param atserver_port port of secondary. if you do not know the port, you can use
 * atclient_utils_find_atserver_address,
 * @param atkeys populated atkeys, especially with the pkam private key
 * @param atsign the atsign the atkeys belong to, this string is assumed to be null terminated
 * @return int 0 on success, non-zero on error
 */
int atclient_pkam_authenticate(atclient *ctx, const char *atsign, const atclient_atkeys *atkeys, atclient_pkam_authenticate_options *options);

/**
 * @brief Put a string value into a self key into your atServer. Putting a self key is a private value and is encrypted only for you
 *
 * @param ctx the atclient context, must be initialized with atclient_init() and authenticated via
 * atclient_pkam_authenticate()
 * @param atkey the atkey to put the value into, must be initialized with atclient_atkey_init() and have populated
 * values (sharedby, key and optionally namespace)
 * @param value the value to put into the atServer, assumed to be non-null and null-terminated
 * @param request_options the options for the put operation, can be NULL if you don't need to set any options
 * @param commit_id the output commit_id of the put operation that the atServer returns, can be NULL if you don't care
 * about the commit_id
 * @return int 0 on success
 */
int atclient_put_self_key(atclient *ctx, atclient_atkey *atkey, const char *value,
                          const atclient_put_self_key_request_options *request_options, int *commit_id);

/**
 * @brief Put a string value into a shared key into your atServer. Putting a shared key is a shared value and is encrypted for you and the person you shared it with
 *
 * @param ctx the atclient context, must be initialized with atclient_init() and authenticated via
 * atclient_pkam_authenticate()
 * @param atkey the atkey to put the value into, must be initialized with atclient_atkey_init() and have populated
 * values (sharedby, key and optionally namespace)
 * @param value the value to put into the atServer, assumed to be non-null and null-terminated
 * @param request_options the options for the put operation, can be NULL if you don't need to set any options
 * @param commit_id the output commit_id of the put operation that the atServer returns, can be NULL if you don't care
 * about the commit_id
 * @return int 0 on success
 */
int atclient_put_shared_key(atclient *ctx, atclient_atkey *atkey, const char *value,
                            const atclient_put_shared_key_request_options *request_options, int *commit_id);

/**
 * @brief Put a string value into a public key into your atServer. Putting a public key is a public value and not encrypted
 * 
 * @param ctx the atclient context, must be initialized with atclient_init() and authenticated via atclient_pkam_authenticate()
 * @param atkey the atkey to put the value into, must be initialized with atclient_atkey_init() and have populated values (sharedby, key and optionally namespace)
 * @param value the value to put into the atServer, assumed to be non-null and null-terminated
 * @param request_options the options for the put operation, can be NULL if you don't need to set any options
 * @param commit_id the output commit_id of the put operation that the atServer returns, can be NULL if you don't care about the commit_id
 * @return int 0 on success
 */
int atclient_put_public_key(atclient *ctx, atclient_atkey *atkey, const char *value, const atclient_put_public_key_request_options *request_options, int *commit_id);

/**
 * @brief Get a string value from your atServer.
 * `atclient` must satisfy two conditions before calling this function:
 * 1. initialized with atclient_init()
 * 2. authenticated via atclient_pkam_authenticate()
 *
 * `atkey` must satisfy the following condition before calling this function:
 * 1. initialized with atclient_atkey_init()
 * 2. have populated values (such as a name, shared_by, shared_with, etc,.) depending on what kind of atkey you want to
 * be associated with your value.
 *
 * @param atclient the atclient context (must satisfy the two conditions stated above)
 * @param atkey the populated atkey to get the value from (must satisfy the two conditions stated above)
 * @param value double pointer to hold value gotten from atServer, can be NULL if you don't need the value, if it is non-null, caller is responsible for freeing the memory
 * @param value_len the size of the buffer to hold the value gotten from atServer
 * @return int 0 on success
 */
int atclient_get_self_key(atclient *atclient, atclient_atkey *atkey, char **value, const atclient_get_self_key_request_options *request_options);

/**
 * @brief Get a publickey from your atServer or another atServer
 * `atclient` must satisfy two conditions before calling this function:
 * 1. initialized with atclient_init()
 * 2. authenticated via atclient_pkam_authenticate()
 *
 * `atkey` must satisfy the following condition before calling this function:
 * 1. initialized with atclient_atkey_init()
 * 2. have populated values (such as a name, shared_by, shared_with, etc,.) depending on what kind of atkey you want to
 * be associated with your value.
 *
 * @param atclient the atclient context (must satisfy the two conditions stated above)
 * @param atkey the populated atkey to get the value from (must satisfy the two conditions stated above)
 * @param value double pointer to hold value gotten from atServer, can be NULL if you don't need the value, if it is non-null, caller is responsible for freeing the memory
 * @param request_options the options for the get operation, can be NULL if you don't need to set any options
 * @return int 0 on success
 */
int atclient_get_public_key(atclient *atclient, atclient_atkey *atkey, char **value, atclient_get_public_key_request_options *request_options);

/**
 * @brief Get a sharedkey either shared by you or shared with you and receive the decrypted plaintext value.
 * `atclient` must satisfy two conditions before calling this function:
 * 1. initialized with atclient_init()
 * 2. authenticated via atclient_pkam_authenticate()
 *
 * `atkey` must satisfy the following condition before calling this function:
 * 1. initialized with atclient_atkey_init()
 * 2. have populated values (such as a name, shared_by, shared_with, etc,.) depending on what kind of atkey you want to
 * be associated with your value.
 *
 * @param atclient The atclient context (must satisfy the two conditions stated above)
 * @param atkey The populated atkey to get the value from (must satisfy the two conditions stated above)
 * @param value A pointer that will be allocated for you to hold value gotten from atServer, can be NULL if you don't need the value, if it is non-null, caller is responsible for freeing the memory
 * @param request_options The options for the get operation, can be NULL if you don't need to set any options
 * @return int 0 on success
 */
int atclient_get_shared_key(atclient *atclient, atclient_atkey *atkey, char **value, const atclient_get_shared_key_request_options *request_options);

/**
 * @brief Delete an atkey from your atserver
 * `atclient` must satisfy two conditions before calling this function:
 * 1. initialized with atclient_init()
 * 2. authenticated via atclient_pkam_authenticate()
 *
 * `atkey` must satisfy the following condition before calling this function:
 * 1. initialized with atclient_atkey_init()
 * 2. have populated values (such as a name, shared_by, shared_with, etc,.) depending on what kind of atkey you want to
 * be associated with your value.
 *
 * @param atclient the atclient context (must satisfy the two conditions stated above)
 * @param atkey the populated atkey to delete from atServer (must satisfy the two conditions stated above)
 * @param options the options for the delete operation
 * @param commit_id the output commit_id of the delete operation that the atServer returns, can be set to NULL if you do
 * not need it
 * @return int 0 on success
 */
int atclient_delete(atclient *atclient, const atclient_atkey *atkey, const atclient_delete_request_options *options,
                    int *commit_id);

/**
 * @brief Runs a scan of the atServer to see what atKeys you have.
 *
 * @param atclient the initialized and pkam_authenticated atclient context
 * @param regex (input): the regex pattern for what keys to filter
 * @param show_hidden (input): true to show "hidden" keys (which are keys that begin with an _), false otherwise
 * @param recv_buffer_size (input): the size of the buffer to receive the response from the atServer
 * @param atkey (output): a double pointer which will be a pointer to the first atkey in the array. caller of this
 * function is responsible for each individual atkey in the array using `atclient_atkey_free`
 * @param output_array_len (output): the overall size of the array that was allocated
 * @return int 0 on success
 */
int atclient_get_atkeys(atclient *atclient, atclient_atkey **atkey, size_t *output_array_len, const atclient_get_atkeys_request_options *request_options);

/**
 * @brief Send a heartbeat (noop)
 * @param heartbeat_conn the initialized and pkam authenticated atclient context to send the heartbeat
 * @return 0 on success, non-zero on error
 *
 * @note Ideally this is scheduled to be sent every 30 seconds
 * @note this is different than a normal noop command, since we don't listen for the response from the server
 * @note It is the responsibility of the caller to ensure that the connection is still alive
 */
int atclient_send_heartbeat(atclient *heartbeat_conn);

/**
 * @brief Checks if the atclient is connected to the atserver
 *
 * @param ctx the atclient context, must be initialized
 * @return true, if connected, false otherwise
 */
bool atclient_is_connected(atclient *ctx);

/**
 * @brief For any atclient SSL operations (such as the crud operations like put,get,delete or event operations like
 * notify), the timeout will be set to this value. Once an operation is ran (mbedtls_ssl_read), it will wait at most
 * `timeout_ms` before returning. If any bytes are read, it will return immediately. If no bytes are read, it will
 * return after `timeout_ms` milliseconds.
 *
 * @param ctx the pkam_authenticated atclient context
 * @param timeout_ms the timeout in milliseconds
 */
void atclient_set_read_timeout(atclient *ctx, int timeout_ms);

#endif
