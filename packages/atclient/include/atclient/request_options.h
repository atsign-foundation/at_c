#ifndef ATCLIENT_REQUEST_OPTIONS_H
#define ATCLIENT_REQUEST_OPTIONS_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define VALUE_INITIALIZED 0b00000001

#define ATCLIENT_PUT_SELF_KEY_REQUEST_OPTIONS_SHARED_ENCRYPTION_KEY_INDEX 0
#define ATCLIENT_PUT_SELF_KEY_REQUEST_OPTIONS_SHARED_ENCRYPTION_KEY_INITIALIZED (VALUE_INITIALIZED << 0)

#define ATCLIENT_PUT_SHARED_KEY_REQUEST_OPTIONS_SHARED_ENCRYPTION_KEY_INDEX 0
#define ATCLIENT_PUT_SHARED_KEY_REQUEST_OPTIONS_BYPASS_CACHE_INDEX 0
#define ATCLIENT_PUT_SHARED_KEY_REQUEST_OPTIONS_SHARED_ENCRYPTION_KEY_INITIALIZED (VALUE_INITIALIZED << 0)
#define ATCLIENT_PUT_SHARED_KEY_REQUEST_OPTIONS_BYPASS_CACHE_INITIALIZED (VALUE_INITIALIZED << 1)

#define ATCLIENT_GET_SELF_KEY_REQUEST_OPTIONS_SHARED_ENCRYPTION_KEY_INDEX 0
#define ATCLIENT_GET_SELF_KEY_REQUEST_OPTIONS_STORE_ATKEY_METADATA_INDEX 0
#define ATCLIENT_GET_SELF_KEY_REQUEST_OPTIONS_SHARED_ENCRYPTION_KEY_INITIALIZED (VALUE_INITIALIZED << 0)
#define ATCLIENT_GET_SELF_KEY_REQUEST_OPTIONS_STORE_ATKEY_METADATA_INITIALIZED (VALUE_INITIALIZED << 1)

#define ATCLIENT_GET_SHARED_KEY_REQUEST_OPTIONS_SHARED_ENCRYPTION_KEY_INDEX 0
#define ATCLIENT_GET_SHARED_KEY_REQUEST_OPTIONS_STORE_ATKEY_METADATA_INDEX 0
#define ATCLIENT_GET_SHARED_KEY_REQUEST_OPTIONS_SHARED_ENCRYPTION_KEY_INITIALIZED (VALUE_INITIALIZED << 0)
#define ATCLIENT_GET_SHARED_KEY_REQUEST_OPTIONS_STORE_ATKEY_METADATA_INITIALIZED (VALUE_INITIALIZED << 1)

#define ATCLIENT_GET_PUBLIC_KEY_REQUEST_OPTIONS_BYPASS_CACHE_INDEX 0
#define ATCLIENT_GET_PUBLIC_KEY_REQUEST_OPTIONS_STORE_ATKEY_METADATA_INDEX 0
#define ATCLIENT_GET_PUBLIC_KEY_REQUEST_OPTIONS_BYPASS_CACHE_INITIALIZED (VALUE_INITIALIZED << 0)
#define ATCLIENT_GET_PUBLIC_KEY_REQUEST_OPTIONS_STORE_ATKEY_METADATA_INITIALIZED (VALUE_INITIALIZED << 1)

#define ATCLIENT_DELETE_REQUEST_OPTIONS_INDEX 0
#define ATCLIENT_DELETE_REQUEST_OPTIONS_INITIALIZED (VALUE_INITIALIZED << 0)

#define ATCLIENT_GET_ATKEYS_REQUEST_OPTIONS_REGEX_INDEX 0
#define ATCLIENT_GET_ATKEYS_REQUEST_OPTIONS_SHOW_HIDDEN_INDEX 0

#define ATCLIENT_GET_ATKEYS_REQUEST_OPTIONS_REGEX_INITIALIZED (VALUE_INITIALIZED << 0)
#define ATCLIENT_GET_ATKEYS_REQUEST_OPTIONS_SHOW_HIDDEN_INITIALIZED (VALUE_INITIALIZED << 1)

/*
 * 1A. Put SelfKey
 */
typedef struct atclient_put_self_key_request_options {
  // empty for now
  // kept for future proofing
} atclient_put_self_key_request_options;

/*
 * 1B. Put SharedKey
 */
typedef struct atclient_put_shared_key_request_options {
  unsigned char *shared_encryption_key;
  unsigned char *iv;
  bool bypass_cache;
  uint8_t _initialized_fields[1];
} atclient_put_shared_key_request_options;

/*
 * 1C. Put PublicKey
 */
typedef struct atclient_put_public_key_request_options {
    // empty for now
    // kept for future proofing
  uint8_t _initialized_fields[1];
} atclient_put_public_key_request_options;

/*
 * 2A. Get SelfKey
 */
typedef struct atclient_get_self_key_request_options {
  bool store_atkey_metadata;
  uint8_t _initialized_fields[1];
} atclient_get_self_key_request_options;

/*
 * 2B. Get SharedKey
 */
typedef struct atclient_get_shared_key_request_options {
  unsigned char *shared_encryption_key;
  bool store_atkey_metadata;
  uint8_t _initialized_fields[1];
} atclient_get_shared_key_request_options;

/*
 * 2C. Get PublicKey
 */
typedef struct atclient_get_public_key_request_options {
  bool bypass_cache;
  bool store_atkey_metadata;
  uint8_t _initialized_fields[1];
} atclient_get_public_key_request_options;

/*
 * 3. Delete
 */
typedef struct atclient_delete_request_options {
  // empty
  // future proofing
  uint8_t _initialized_fields[1];
} atclient_delete_request_options;

/*
 * 4. Get_AtKeys Request Options
 */

typedef struct atclient_get_atkeys_request_options {
  char *regex;
  bool show_hidden;
  uint8_t _initialized_fields[1];
} atclient_get_atkeys_request_options;

/*
 * 1A. Put SelfKey
 */
void atclient_put_self_key_request_options_init(atclient_put_self_key_request_options *options);
void atclient_put_self_key_request_options_free(atclient_put_self_key_request_options *options);

/*
 * 1B. Put SharedKey
 */
void atclient_put_shared_key_request_options_init(atclient_put_shared_key_request_options *options);
void atclient_put_shared_key_request_options_free(atclient_put_shared_key_request_options *options);

bool atclient_put_shared_key_request_options_is_shared_encryption_key_initialized(
    const atclient_put_shared_key_request_options *options);
void atclient_put_shared_key_request_options_set_shared_encryption_key_initialized(
    atclient_put_shared_key_request_options *options, const bool initialized);
int atclient_put_shared_key_request_options_set_shared_encryption_key(atclient_put_shared_key_request_options *options,
                                                                      const unsigned char *shared_encryption_key);
void atclient_put_shared_key_request_options_unset_shared_encryption_key(
    atclient_put_shared_key_request_options *options);

bool atclient_put_shared_key_request_options_is_bypass_cache_initialized(
    const atclient_put_shared_key_request_options *options);
void atclient_put_shared_key_request_options_set_bypass_cache_initialized(
    atclient_put_shared_key_request_options *options, const bool initialized);
int atclient_put_shared_key_request_options_set_bypass_cache(atclient_put_shared_key_request_options *options,
                                                             const bool bypass_cache);
void atclient_put_shared_key_request_options_unset_bypass_cache(atclient_put_shared_key_request_options *options);

/*
 * 1C. Put PublicKey
 */
void atclient_put_public_key_request_options_init(atclient_put_public_key_request_options *options);
void atclient_put_public_key_request_options_free(atclient_put_public_key_request_options *options);

/*
 * 2A. Get SelfKey
 */
void atclient_get_self_key_request_options_init(atclient_get_self_key_request_options *options);
void atclient_get_self_key_request_options_free(atclient_get_self_key_request_options *options);

bool atclient_get_self_key_request_options_is_store_atkey_metadata_initialized(
    const atclient_get_self_key_request_options *options);
void atclient_get_self_key_request_options_set_store_atkey_metadata_initialized(
    atclient_get_self_key_request_options *options, const bool initialized);
int atclient_get_self_key_request_options_set_store_atkey_metadata(atclient_get_self_key_request_options *options,
                                                                   const bool store_atkey_metadata);
void atclient_get_self_key_request_options_unset_store_atkey_metadata(atclient_get_self_key_request_options *options);

/*
 * 2B. Get SharedKey
 */
void atclient_get_shared_key_request_options_init(atclient_get_shared_key_request_options *options);
void atclient_get_shared_key_request_options_free(atclient_get_shared_key_request_options *options);

bool atclient_get_shared_key_request_options_is_shared_encryption_key_initialized(
    const atclient_get_shared_key_request_options *options);
void atclient_get_shared_key_request_options_set_shared_encryption_key_initialized(
    atclient_get_shared_key_request_options *options, const bool initialized);
int atclient_get_shared_key_request_options_set_shared_encryption_key(atclient_get_shared_key_request_options *options,
                                                                      const unsigned char *shared_encryption_key);
void atclient_get_shared_key_request_options_unset_shared_encryption_key(
    atclient_get_shared_key_request_options *options);

bool atclient_get_shared_key_request_options_is_store_atkey_metadata_initialized(
    const atclient_get_shared_key_request_options *options);
void atclient_get_shared_key_request_options_set_store_atkey_metadata_initialized(
    atclient_get_shared_key_request_options *options, const bool initialized);
int atclient_get_shared_key_request_options_set_store_atkey_metadata(atclient_get_shared_key_request_options *options,
                                                                     const bool store_atkey_metadata);
void atclient_get_shared_key_request_options_unset_store_atkey_metadata(
    atclient_get_shared_key_request_options *options);

/*
 * 2C. Get PublicKey
 */
void atclient_get_public_key_request_options_init(atclient_get_public_key_request_options *options);
void atclient_get_public_key_request_options_free(atclient_get_public_key_request_options *options);

bool atclient_get_public_key_request_options_is_bypass_cache_initialized(
    const atclient_get_public_key_request_options *options);
void atclient_get_public_key_request_options_set_bypass_cache_initialized(
    atclient_get_public_key_request_options *options, const bool initialized);
int atclient_get_public_key_request_options_set_bypass_cache(atclient_get_public_key_request_options *options,
                                                             const bool bypass_cache);
void atclient_get_public_key_request_options_unset_bypass_cache(atclient_get_public_key_request_options *options);

bool atclient_get_public_key_request_options_is_store_atkey_metadata_initialized(
    const atclient_get_public_key_request_options *options);
void atclient_get_public_key_request_options_set_store_atkey_metadata_initialized(
    atclient_get_public_key_request_options *options, const bool initialized);
int atclient_get_public_key_request_options_set_store_atkey_metadata(atclient_get_public_key_request_options *options,
                                                                     const bool store_atkey_metadata);
void atclient_get_public_key_request_options_unset_store_atkey_metadata(
    atclient_get_public_key_request_options *options);

/*
 * 3. Delete
 */
void atclient_delete_request_options_init(atclient_delete_request_options *options);
void atclient_delete_request_options_free(atclient_delete_request_options *options);

/*
 * 4. Get_AtKeys Request Options
 */

void atclient_get_atkeys_request_options_init(atclient_get_atkeys_request_options *options);
void atclient_get_atkeys_request_options_free(atclient_get_atkeys_request_options *options);

bool atclient_get_atkeys_request_options_is_regex_initialized(const atclient_get_atkeys_request_options *options);
void atclient_get_atkeys_request_options_set_regex_initialized(atclient_get_atkeys_request_options *options,
                                                               const bool initialized);
int atclient_get_atkeys_request_options_set_regex(atclient_get_atkeys_request_options *options, const char *regex);
void atclient_get_atkeys_request_options_unset_regex(atclient_get_atkeys_request_options *options);

bool atclient_get_atkeys_request_options_is_show_hidden_initialized(const atclient_get_atkeys_request_options *options);
void atclient_get_atkeys_request_options_set_show_hidden_initialized(atclient_get_atkeys_request_options *options,
                                                                     const bool initialized);
int atclient_get_atkeys_request_options_set_show_hidden(atclient_get_atkeys_request_options *options,
                                                        const bool show_hidden);
void atclient_get_atkeys_request_options_unset_show_hidden(atclient_get_atkeys_request_options *options);

#endif
