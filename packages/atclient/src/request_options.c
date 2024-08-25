#include <atchops/aes.h>
#include <atclient/constants.h>
#include <atclient/request_options.h>
#include <atlogger/atlogger.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>

#define TAG "request_options"

// default param values for ATCLIENT PKAM AUTHENTICATE OPTIONS
#define ATCLIENT_PKAM_AUTHENTICATE_DEFAULT_ROOT_SERVER_HOST "root.atsign.org"
#define ATCLIENT_PKAM_AUTHENTICATE_DEFAULT_ROOT_SERVER_PORT 64

static void atclient_put_shared_key_request_options_set_shared_encryption_key_initialized(
    atclient_put_shared_key_request_options *options, const bool initialized);
static void atclient_put_shared_key_request_options_set_iv_initialized(atclient_put_shared_key_request_options *options,
                                                                       const bool initialized);
static void atclient_get_self_key_request_options_set_store_atkey_metadata_initialized(
    atclient_get_self_key_request_options *options, const bool initialized);
static void atclient_get_shared_key_request_options_set_shared_encryption_key_initialized(
    atclient_get_shared_key_request_options *options, const bool initialized);
static void atclient_get_shared_key_request_options_set_iv_initialized(atclient_get_shared_key_request_options *options,
                                                                       const bool initialized);
static void
atclient_get_shared_key_request_options_set_bypass_cache_initialized(atclient_get_shared_key_request_options *options,
                                                                     const bool initialized);
static void atclient_get_shared_key_request_options_set_store_atkey_metadata_initialized(
    atclient_get_shared_key_request_options *options, const bool initialized);
static void
atclient_get_public_key_request_options_set_bypass_cache_initialized(atclient_get_public_key_request_options *options,
                                                                     const bool initialized);
static void atclient_get_public_key_request_options_set_store_atkey_metadata_initialized(
    atclient_get_public_key_request_options *options, const bool initialized);
static void atclient_get_atkeys_request_options_set_regex_initialized(atclient_get_atkeys_request_options *options,
                                                                      const bool initialized);
static void
atclient_get_atkeys_request_options_set_show_hidden_initialized(atclient_get_atkeys_request_options *options,
                                                                const bool initialized);

/*
 * =================
 * 1A. Put SelfKey
 * =================
 */
void atclient_put_self_key_request_options_init(atclient_put_self_key_request_options *options) {
  /*
   * 1. Validate arguments
   */
  if (options == NULL) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atclient_put_self_key_request_options_init: Invalid arguments\n");
    return;
  }

  /*
   * 2. Initialize the options
   */
  memset(options, 0, sizeof(atclient_put_self_key_request_options));
}

void atclient_put_self_key_request_options_free(atclient_put_self_key_request_options *options) {
  /*
   * 1. Validate arguments
   */
  if (options == NULL) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atclient_put_self_key_request_options_free: Invalid arguments\n");
    return;
  }

  /*
   * 2. Free the options
   */
}

/*
 * =================
 * 1B. Put SharedKey
 * =================
 */

void atclient_put_shared_key_request_options_init(atclient_put_shared_key_request_options *options) {
  /*
   * 1. Validate arguments
   */
  if (options == NULL) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR,
                 "atclient_put_shared_key_request_options_init: Invalid arguments\n");
    return;
  }

  /*
   * 2. Initialize the options
   */
  memset(options, 0, sizeof(atclient_put_shared_key_request_options));
}

void atclient_put_shared_key_request_options_free(atclient_put_shared_key_request_options *options) {
  /*
   * 1. Validate arguments
   */
  if (options == NULL) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR,
                 "atclient_put_shared_key_request_options_free: Invalid arguments\n");
    return;
  }

  /*
   * 2. Free the options
   */
  if (atclient_put_shared_key_request_options_is_shared_encryption_key_initialized(options)) {
    atclient_put_shared_key_request_options_unset_shared_encryption_key(options);
  }

  if (atclient_put_shared_key_request_options_is_iv_initialized(options)) {
    atclient_put_shared_key_request_options_unset_iv(options);
  }
}

bool atclient_put_shared_key_request_options_is_shared_encryption_key_initialized(
    const atclient_put_shared_key_request_options *options) {

  /*
   * 1. Validate arguments
   */
  if (options == NULL) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR,
                 "atclient_put_shared_key_request_options_is_shared_encryption_key_initialized: "
                 "Invalid arguments\n");
    return false;
  }

  /*
   * 2. Check if the shared encryption key is initialized
   */
  return options->_initialized_fields[ATCLIENT_PUT_SHARED_KEY_REQUEST_OPTIONS_SHARED_ENCRYPTION_KEY_INDEX] &
         ATCLIENT_PUT_SHARED_KEY_REQUEST_OPTIONS_SHARED_ENCRYPTION_KEY_INITIALIZED;
}

static void atclient_put_shared_key_request_options_set_shared_encryption_key_initialized(
    atclient_put_shared_key_request_options *options, const bool initialized) {
  /*
   * 1. Validate arguments
   */
  if (options == NULL) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR,
                 "atclient_put_shared_key_request_options_set_shared_encryption_key_initialized: "
                 "Invalid arguments\n");
    return;
  }

  /*
   * 2. Set the shared encryption key initialized
   */
  if (initialized) {
    options->_initialized_fields[ATCLIENT_PUT_SHARED_KEY_REQUEST_OPTIONS_SHARED_ENCRYPTION_KEY_INDEX] |=
        ATCLIENT_PUT_SHARED_KEY_REQUEST_OPTIONS_SHARED_ENCRYPTION_KEY_INITIALIZED;
  } else {
    options->_initialized_fields[ATCLIENT_PUT_SHARED_KEY_REQUEST_OPTIONS_SHARED_ENCRYPTION_KEY_INDEX] &=
        ~ATCLIENT_PUT_SHARED_KEY_REQUEST_OPTIONS_SHARED_ENCRYPTION_KEY_INITIALIZED;
  }
}
int atclient_put_shared_key_request_options_set_shared_encryption_key(atclient_put_shared_key_request_options *options,
                                                                      const unsigned char *shared_encryption_key) {
  /*
   * 1. Validate arguments
   */
  int ret = 1;

  if (options == NULL) {
    ret = 1;
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR,
                 "atclient_put_shared_key_request_options_set_shared_encryption_key: "
                 "Invalid arguments\n");
    goto exit;
  }

  if (shared_encryption_key == NULL) {
    ret = 1;
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR,
                 "atclient_put_shared_key_request_options_set_shared_encryption_key: "
                 "Invalid arguments\n");
    goto exit;
  }

  /*
   * 2. Unset the shared encryption key, if necessary
   */
  if (atclient_put_shared_key_request_options_is_shared_encryption_key_initialized(options)) {
    atclient_put_shared_key_request_options_unset_shared_encryption_key(options);
  }

  /*
   * 3. Set the shared encryption key
   */

  const size_t shared_encryption_key_size = ATCHOPS_AES_256 / 8;
  if ((options->shared_encryption_key = (unsigned char *)malloc(sizeof(unsigned char) * shared_encryption_key_size)) ==
      NULL) {
    ret = 1;
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR,
                 "atclient_put_shared_key_request_options_set_shared_encryption_key: "
                 "Failed to allocate memory for shared encryption key\n");
    goto exit;
  }

  atclient_put_shared_key_request_options_set_shared_encryption_key_initialized(options, true);
  memcpy(options->shared_encryption_key, shared_encryption_key, shared_encryption_key_size);

  ret = 0;
  goto exit;
exit: { return ret; }
}

void atclient_put_shared_key_request_options_unset_shared_encryption_key(
    atclient_put_shared_key_request_options *options) {
  /*
   * 1. Validate arguments
   */

  if (options == NULL) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR,
                 "atclient_put_shared_key_request_options_unset_shared_encryption_key: "
                 "Invalid arguments\n");
    return;
  }

  /*
   * 2. Unset the shared encryption key
   */
  if (atclient_put_shared_key_request_options_is_shared_encryption_key_initialized(options)) {
    free(options->shared_encryption_key);
  }
  options->shared_encryption_key = NULL;
  atclient_put_shared_key_request_options_set_shared_encryption_key_initialized(options, false);
}

bool atclient_put_shared_key_request_options_is_iv_initialized(const atclient_put_shared_key_request_options *options) {
  /*
   * 1. Validate arguments
   */
  if (options == NULL) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR,
                 "atclient_put_shared_key_request_options_is_iv_initialized: Invalid arguments\n");
    return false;
  }

  /*
   * 2. Check if the IV is initialized
   */
  return options->_initialized_fields[ATCLIENT_PUT_SHARED_KEY_REQUEST_OPTIONS_IV_INDEX] &
         ATCLIENT_PUT_SHARED_KEY_REQUEST_OPTIONS_IV_INITIALIZED;
}

static void atclient_put_shared_key_request_options_set_iv_initialized(atclient_put_shared_key_request_options *options,
                                                                       const bool initialized) {
  /*
   * 1. Validate arguments
   */
  if (options == NULL) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR,
                 "atclient_put_shared_key_request_options_set_iv_initialized: Invalid arguments\n");
    return;
  }

  /*
   * 2. Set the IV initialized
   */
  if (initialized) {
    options->_initialized_fields[ATCLIENT_PUT_SHARED_KEY_REQUEST_OPTIONS_IV_INDEX] |=
        ATCLIENT_PUT_SHARED_KEY_REQUEST_OPTIONS_IV_INITIALIZED;
  } else {
    options->_initialized_fields[ATCLIENT_PUT_SHARED_KEY_REQUEST_OPTIONS_IV_INDEX] &=
        ~ATCLIENT_PUT_SHARED_KEY_REQUEST_OPTIONS_IV_INITIALIZED;
  }
}

int atclient_put_shared_key_request_options_set_iv(atclient_put_shared_key_request_options *options,
                                                   const unsigned char *iv) {
  int ret = 1;

  /*
   * 1. Validate arguments
   */
  if (options == NULL) {
    ret = 1;
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR,
                 "atclient_put_shared_key_request_options_set_iv: Invalid arguments\n");
    goto exit;
  }

  if (iv == NULL) {
    ret = 1;
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR,
                 "atclient_put_shared_key_request_options_set_iv: Invalid arguments\n");
    goto exit;
  }

  /*
   * 2. Unset the IV, if necessary
   */
  if (atclient_put_shared_key_request_options_is_iv_initialized(options)) {
    atclient_put_shared_key_request_options_unset_iv(options);
  }

  /*
   * 3. Set the IV
   */
  const size_t iv_size = ATCHOPS_AES_256 / 8;
  if ((options->iv = (unsigned char *)malloc(sizeof(unsigned char) * iv_size)) == NULL) {
    ret = 1;
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR,
                 "atclient_put_shared_key_request_options_set_iv: Failed to allocate memory for IV\n");
    goto exit;
  }

  atclient_put_shared_key_request_options_set_iv_initialized(options, true);
  memcpy(options->iv, iv, iv_size);

  ret = 0;
  goto exit;
exit: { return ret; }
}

void atclient_put_shared_key_request_options_unset_iv(atclient_put_shared_key_request_options *options) {
  /*
   * 1. Validate arguments
   */
  if (options == NULL) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR,
                 "atclient_put_shared_key_request_options_unset_iv: Invalid arguments\n");
    return;
  }

  /*
   * 2. Unset the IV
   */
  if (atclient_put_shared_key_request_options_is_iv_initialized(options)) {
    free(options->iv);
  }
  options->iv = NULL;
  atclient_put_shared_key_request_options_set_iv_initialized(options, false);
}

/*
 * =================
 * 1C. Put PublicKey
 * =================
 */
void atclient_put_public_key_request_options_init(atclient_put_public_key_request_options *options) {
  /*
   * 1. Validate arguments
   */
  if (options == NULL) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR,
                 "atclient_put_public_key_request_options_init: Invalid arguments\n");
    return;
  }

  /*
   * 2. Initialize the options
   */
  memset(options, 0, sizeof(atclient_put_public_key_request_options));
}

void atclient_put_public_key_request_options_free(atclient_put_public_key_request_options *options) {
  /*
   * 1. Validate arguments
   */
  if (options == NULL) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR,
                 "atclient_put_public_key_request_options_free: Invalid arguments\n");
    return;
  }

  /*
   * 2. Free the options
   */
}

/*
 * =================
 * 2A. Get SelfKey
 * =================
 */
void atclient_get_self_key_request_options_init(atclient_get_self_key_request_options *options) {
  /*
   * 1. Validate arguments
   */
  if (options == NULL) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atclient_get_self_key_request_options_init: Invalid arguments\n");
    return;
  }

  /*
   * 2. Initialize the options
   */
  memset(options, 0, sizeof(atclient_get_self_key_request_options));
}
void atclient_get_self_key_request_options_free(atclient_get_self_key_request_options *options) {
  /*
   * 1. Validate arguments
   */
  if (options == NULL) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atclient_get_self_key_request_options_free: Invalid arguments\n");
    return;
  }

  /*
   * 2. Free the options
   */
  if (atclient_get_self_key_request_options_is_store_atkey_metadata_initialized(options)) {
    atclient_get_self_key_request_options_unset_store_atkey_metadata(options);
  }
}

bool atclient_get_self_key_request_options_is_store_atkey_metadata_initialized(
    const atclient_get_self_key_request_options *options) {
  /*
   * 1. Validate arguments
   */
  if (options == NULL) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR,
                 "atclient_get_self_key_request_options_is_store_atkey_metadata_initialized: Invalid arguments\n");
    return false;
  }

  /*
   * 2. Check if the store atkey metadata is initialized
   */
  return options->_initialized_fields[ATCLIENT_GET_SELF_KEY_REQUEST_OPTIONS_STORE_ATKEY_METADATA_INDEX] &
         ATCLIENT_GET_SELF_KEY_REQUEST_OPTIONS_STORE_ATKEY_METADATA_INITIALIZED;
}

static void atclient_get_self_key_request_options_set_store_atkey_metadata_initialized(
    atclient_get_self_key_request_options *options, const bool initialized) {
  /*
   * 1. Validate arguments
   */
  if (options == NULL) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR,
                 "atclient_get_self_key_request_options_set_store_atkey_metadata_initialized: Invalid arguments\n");
    return;
  }

  /*
   * 2. Set the store atkey metadata initialized
   */
  if (initialized) {
    options->_initialized_fields[ATCLIENT_GET_SELF_KEY_REQUEST_OPTIONS_STORE_ATKEY_METADATA_INDEX] |=
        ATCLIENT_GET_SELF_KEY_REQUEST_OPTIONS_STORE_ATKEY_METADATA_INITIALIZED;
  } else {
    options->_initialized_fields[ATCLIENT_GET_SELF_KEY_REQUEST_OPTIONS_STORE_ATKEY_METADATA_INDEX] &=
        ~ATCLIENT_GET_SELF_KEY_REQUEST_OPTIONS_STORE_ATKEY_METADATA_INITIALIZED;
  }
}

int atclient_get_self_key_request_options_set_store_atkey_metadata(atclient_get_self_key_request_options *options,
                                                                   const bool store_atkey_metadata) {
  int ret = 1;

  /*
   * 1. Validate arguments
   */
  if (options == NULL) {
    ret = 1;
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR,
                 "atclient_get_self_key_request_options_set_store_atkey_metadata: Invalid arguments\n");
    return ret;
  }

  /*
   * 2. Unset the store atkey metadata, if necessary
   */
  if (atclient_get_self_key_request_options_is_store_atkey_metadata_initialized(options)) {
    atclient_get_self_key_request_options_unset_store_atkey_metadata(options);
  }

  /*
   * 3. Set the store atkey metadata
   */
  options->store_atkey_metadata = store_atkey_metadata;
  atclient_get_self_key_request_options_set_store_atkey_metadata_initialized(options, true);

  ret = 0;
  goto exit;
exit: { return ret; }
}

void atclient_get_self_key_request_options_unset_store_atkey_metadata(atclient_get_self_key_request_options *options) {
  /*
   * 1. Validate arguments
   */
  if (options == NULL) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR,
                 "atclient_get_self_key_request_options_unset_store_atkey_metadata: Invalid arguments\n");
    return;
  }

  /*
   * 2. Unset the store atkey metadata
   */
  options->store_atkey_metadata = false;
  atclient_get_self_key_request_options_set_store_atkey_metadata_initialized(options, false);
}

/*
 * =================
 * 2B. Get SharedKey
 * =================
 */
void atclient_get_shared_key_request_options_init(atclient_get_shared_key_request_options *options) {
  /*
   * 1. Validate arguments
   */
  if (options == NULL) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR,
                 "atclient_get_shared_key_request_options_init: Invalid arguments\n");
    return;
  }

  /*
   * 2. Initialize the options
   */
  memset(options, 0, sizeof(atclient_get_shared_key_request_options));
}

void atclient_get_shared_key_request_options_free(atclient_get_shared_key_request_options *options) {
  /*
   * 1. Validate arguments
   */
  if (options == NULL) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR,
                 "atclient_get_shared_key_request_options_free: Invalid arguments\n");
    return;
  }

  /*
   * 2. Free the options
   */
  if (atclient_get_shared_key_request_options_is_shared_encryption_key_initialized(options)) {
    atclient_get_shared_key_request_options_unset_shared_encryption_key(options);
  }

  if (atclient_get_shared_key_request_options_is_iv_initialized(options)) {
    atclient_get_shared_key_request_options_unset_iv(options);
  }

  if (atclient_get_shared_key_request_options_is_bypass_cache_initialized(options)) {
    atclient_get_shared_key_request_options_unset_bypass_cache(options);
  }

  if (atclient_get_shared_key_request_options_is_store_atkey_metadata_initialized(options)) {
    atclient_get_shared_key_request_options_unset_store_atkey_metadata(options);
  }
}

bool atclient_get_shared_key_request_options_is_shared_encryption_key_initialized(
    const atclient_get_shared_key_request_options *options) {
  /*
   * 1. Validate arguments
   */
  if (options == NULL) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR,
                 "atclient_get_shared_key_request_options_is_shared_encryption_key_initialized: Invalid arguments\n");
    return false;
  }

  /*
   * 2. Check if the shared encryption key is initialized
   */
  return options->_initialized_fields[ATCLIENT_GET_SHARED_KEY_REQUEST_OPTIONS_SHARED_ENCRYPTION_KEY_INDEX] &
         ATCLIENT_GET_SHARED_KEY_REQUEST_OPTIONS_SHARED_ENCRYPTION_KEY_INITIALIZED;
}

static void atclient_get_shared_key_request_options_set_shared_encryption_key_initialized(
    atclient_get_shared_key_request_options *options, const bool initialized) {
  /*
   * 1. Validate arguments
   */
  if (options == NULL) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR,
                 "atclient_get_shared_key_request_options_set_shared_encryption_key_initialized: "
                 "Invalid arguments\n");
    return;
  }

  /*
   * 2. Set the shared encryption key initialized
   */
  if (initialized) {
    options->_initialized_fields[ATCLIENT_GET_SHARED_KEY_REQUEST_OPTIONS_SHARED_ENCRYPTION_KEY_INDEX] |=
        ATCLIENT_GET_SHARED_KEY_REQUEST_OPTIONS_SHARED_ENCRYPTION_KEY_INITIALIZED;
  } else {
    options->_initialized_fields[ATCLIENT_GET_SHARED_KEY_REQUEST_OPTIONS_SHARED_ENCRYPTION_KEY_INDEX] &=
        ~ATCLIENT_GET_SHARED_KEY_REQUEST_OPTIONS_SHARED_ENCRYPTION_KEY_INITIALIZED;
  }
}

int atclient_get_shared_key_request_options_set_shared_encryption_key(atclient_get_shared_key_request_options *options,
                                                                      const unsigned char *shared_encryption_key) {
  int ret = 1;

  /*
   * 1. Validate arguments
   */
  if (options == NULL) {
    ret = 1;
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR,
                 "atclient_get_shared_key_request_options_set_shared_encryption_key: "
                 "Invalid arguments\n");
    goto exit;
  }

  if (shared_encryption_key == NULL) {
    ret = 1;
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR,
                 "atclient_get_shared_key_request_options_set_shared_encryption_key: "
                 "Invalid arguments\n");
    goto exit;
  }

  /*
   * 2. Unset the shared encryption key, if necessary
   */
  if (atclient_get_shared_key_request_options_is_shared_encryption_key_initialized(options)) {
    atclient_get_shared_key_request_options_unset_shared_encryption_key(options);
  }

  /*
   * 3. Set the shared encryption key
   */
  const size_t shared_encryption_key_size = ATCHOPS_AES_256 / 8;
  if ((options->shared_encryption_key = (unsigned char *)malloc(sizeof(unsigned char) * shared_encryption_key_size)) ==
      NULL) {
    ret = 1;
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR,
                 "atclient_get_shared_key_request_options_set_shared_encryption_key: "
                 "Failed to allocate memory for shared encryption key\n");
    goto exit;
  }

  atclient_get_shared_key_request_options_set_shared_encryption_key_initialized(options, true);
  memcpy(options->shared_encryption_key, shared_encryption_key, shared_encryption_key_size);

  ret = 0;
  goto exit;
exit: { return ret; }
}

void atclient_get_shared_key_request_options_unset_shared_encryption_key(
    atclient_get_shared_key_request_options *options) {
  /*
   * 1. Validate arguments
   */
  if (options == NULL) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR,
                 "atclient_get_shared_key_request_options_unset_shared_encryption_key: "
                 "Invalid arguments\n");
    return;
  }

  /*
   * 2. Unset the shared encryption key
   */
  if (atclient_get_shared_key_request_options_is_shared_encryption_key_initialized(options)) {
    free(options->shared_encryption_key);
  }
  options->shared_encryption_key = NULL;
  atclient_get_shared_key_request_options_set_shared_encryption_key_initialized(options, false);
}

bool atclient_get_shared_key_request_options_is_iv_initialized(const atclient_get_shared_key_request_options *options) {
  /*
   * 1. Validate arguments
   */
  if (options == NULL) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR,
                 "atclient_get_shared_key_request_options_is_iv_initialized: Invalid arguments\n");
    return false;
  }

  /*
   * 2. Check if the IV is initialized
   */
  return options->_initialized_fields[ATCLIENT_GET_SHARED_KEY_REQUEST_OPTIONS_IV_INDEX] &
         ATCLIENT_GET_SHARED_KEY_REQUEST_OPTIONS_IV_INITIALIZED;
}

static void atclient_get_shared_key_request_options_set_iv_initialized(atclient_get_shared_key_request_options *options,
                                                                       const bool initialized) {
  /*
   * 1. Validate arguments
   */
  if (options == NULL) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR,
                 "atclient_get_shared_key_request_options_set_iv_initialized: Invalid arguments\n");
    return;
  }

  /*
   * 2. Set the IV initialized
   */
  if (initialized) {
    options->_initialized_fields[ATCLIENT_GET_SHARED_KEY_REQUEST_OPTIONS_IV_INDEX] |=
        ATCLIENT_GET_SHARED_KEY_REQUEST_OPTIONS_IV_INITIALIZED;
  } else {
    options->_initialized_fields[ATCLIENT_GET_SHARED_KEY_REQUEST_OPTIONS_IV_INDEX] &=
        ~ATCLIENT_GET_SHARED_KEY_REQUEST_OPTIONS_IV_INITIALIZED;
  }
}

int atclient_get_shared_key_request_options_set_iv(atclient_get_shared_key_request_options *options,
                                                   const unsigned char *iv) {
  int ret = 1;

  /*
   * 1. Validate arguments
   */
  if (options == NULL) {
    ret = 1;
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR,
                 "atclient_get_shared_key_request_options_set_iv: Invalid arguments\n");
    goto exit;
  }

  if (iv == NULL) {
    ret = 1;
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR,
                 "atclient_get_shared_key_request_options_set_iv: Invalid arguments\n");
    goto exit;
  }

  /*
   * 2. Unset the IV, if necessary
   */
  if (atclient_get_shared_key_request_options_is_iv_initialized(options)) {
    atclient_get_shared_key_request_options_unset_iv(options);
  }

  /*
   * 3. Set the IV
   */
  const size_t iv_size = ATCHOPS_AES_256 / 8;
  if ((options->iv = (unsigned char *)malloc(sizeof(unsigned char) * iv_size)) == NULL) {
    ret = 1;
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR,
                 "atclient_get_shared_key_request_options_set_iv: Failed to allocate memory for IV\n");
    goto exit;
  }

  atclient_get_shared_key_request_options_set_iv_initialized(options, true);
  memcpy(options->iv, iv, iv_size);

  ret = 0;
  goto exit;
exit: { return ret; }
}

void atclient_get_shared_key_request_options_unset_iv(atclient_get_shared_key_request_options *options) {
  /*
   * 1. Validate arguments
   */
  if (options == NULL) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR,
                 "atclient_get_shared_key_request_options_unset_iv: Invalid arguments\n");
    return;
  }

  /*
   * 2. Unset the IV
   */
  if (atclient_get_shared_key_request_options_is_iv_initialized(options)) {
    free(options->iv);
  }
  options->iv = NULL;
  atclient_get_shared_key_request_options_set_iv_initialized(options, false);
}

bool atclient_get_shared_key_request_options_is_bypass_cache_initialized(
    const atclient_get_shared_key_request_options *options) {
  /*
   * 1. Validate arguments
   */
  if (options == NULL) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR,
                 "atclient_get_shared_key_request_options_is_bypass_cache_initialized: "
                 "Invalid arguments\n");
    return false;
  }

  /*
   * 2. Check if the bypass cache is initialized
   */
  return options->_initialized_fields[ATCLIENT_GET_SHARED_KEY_REQUEST_OPTIONS_BYPASS_CACHE_INDEX] &
         ATCLIENT_GET_SHARED_KEY_REQUEST_OPTIONS_BYPASS_CACHE_INITIALIZED;
}

static void
atclient_get_shared_key_request_options_set_bypass_cache_initialized(atclient_get_shared_key_request_options *options,
                                                                     const bool initialized) {
  /*
   * 1. Validate arguments
   */
  if (options == NULL) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR,
                 "atclient_get_shared_key_request_options_set_bypass_cache_initialized: "
                 "Invalid arguments\n");
    return;
  }

  /*
   * 2. Set the bypass cache initialized
   */
  if (initialized) {
    options->_initialized_fields[ATCLIENT_GET_SHARED_KEY_REQUEST_OPTIONS_BYPASS_CACHE_INDEX] |=
        ATCLIENT_GET_SHARED_KEY_REQUEST_OPTIONS_BYPASS_CACHE_INITIALIZED;
  } else {
    options->_initialized_fields[ATCLIENT_GET_SHARED_KEY_REQUEST_OPTIONS_BYPASS_CACHE_INDEX] &=
        ~ATCLIENT_GET_SHARED_KEY_REQUEST_OPTIONS_BYPASS_CACHE_INITIALIZED;
  }
}

int atclient_get_shared_key_request_options_set_bypass_cache(atclient_get_shared_key_request_options *options,
                                                             const bool bypass_cache) {
  int ret = 1;

  /*
   * 1. Validate arguments
   */
  if (options == NULL) {
    ret = 1;
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR,
                 "atclient_get_shared_key_request_options_set_bypass_cache: "
                 "Invalid arguments\n");
    goto exit;
  }

  /*
   * 2. Unset the bypass cache, if necessary
   */
  if (atclient_get_shared_key_request_options_is_bypass_cache_initialized(options)) {
    atclient_get_shared_key_request_options_unset_bypass_cache(options);
  }

  /*
   * 3. Set the bypass cache
   */
  options->bypass_cache = bypass_cache;
  atclient_get_shared_key_request_options_set_bypass_cache_initialized(options, true);

  ret = 0;
  goto exit;
exit: { return ret; }
}

void atclient_get_shared_key_request_options_unset_bypass_cache(atclient_get_shared_key_request_options *options) {
  /*
   * 1. Validate arguments
   */
  if (options == NULL) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR,
                 "atclient_get_shared_key_request_options_unset_bypass_cache: "
                 "Invalid arguments\n");
    return;
  }

  /*
   * 2. Unset the bypass cache
   */
  options->bypass_cache = false;
  atclient_get_shared_key_request_options_set_bypass_cache_initialized(options, false);
}

bool atclient_get_shared_key_request_options_is_store_atkey_metadata_initialized(
    const atclient_get_shared_key_request_options *options) {
  /*
   * 1. Validate arguments
   */
  if (options == NULL) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR,
                 "atclient_get_shared_key_request_options_is_store_atkey_metadata_initialized: "
                 "Invalid arguments\n");
    return false;
  }

  /*
   * 2. Check if the store atkey metadata is initialized
   */
  return options->_initialized_fields[ATCLIENT_GET_SHARED_KEY_REQUEST_OPTIONS_STORE_ATKEY_METADATA_INDEX] &
         ATCLIENT_GET_SHARED_KEY_REQUEST_OPTIONS_STORE_ATKEY_METADATA_INITIALIZED;
}

static void atclient_get_shared_key_request_options_set_store_atkey_metadata_initialized(
    atclient_get_shared_key_request_options *options, const bool initialized) {
  /*
   * 1. Validate arguments
   */
  if (options == NULL) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR,
                 "atclient_get_shared_key_request_options_set_store_atkey_metadata_initialized: "
                 "Invalid arguments\n");
    return;
  }

  /*
   * 2. Set the store atkey metadata initialized
   */
  if (initialized) {
    options->_initialized_fields[ATCLIENT_GET_SHARED_KEY_REQUEST_OPTIONS_STORE_ATKEY_METADATA_INDEX] |=
        ATCLIENT_GET_SHARED_KEY_REQUEST_OPTIONS_STORE_ATKEY_METADATA_INITIALIZED;
  } else {
    options->_initialized_fields[ATCLIENT_GET_SHARED_KEY_REQUEST_OPTIONS_STORE_ATKEY_METADATA_INDEX] &=
        ~ATCLIENT_GET_SHARED_KEY_REQUEST_OPTIONS_STORE_ATKEY_METADATA_INITIALIZED;
  }
}

int atclient_get_shared_key_request_options_set_store_atkey_metadata(atclient_get_shared_key_request_options *options,
                                                                     const bool store_atkey_metadata) {
  int ret = 1;

  /*
   * 1. Validate arguments
   */
  if (options == NULL) {
    ret = 1;
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR,
                 "atclient_get_shared_key_request_options_set_store_atkey_metadata: "
                 "Invalid arguments\n");
    goto exit;
  }

  /*
   * 2. Unset the store atkey metadata, if necessary
   */
  if (atclient_get_shared_key_request_options_is_store_atkey_metadata_initialized(options)) {
    atclient_get_shared_key_request_options_unset_store_atkey_metadata(options);
  }

  /*
   * 3. Set the store atkey metadata
   */
  options->store_atkey_metadata = store_atkey_metadata;
  atclient_get_shared_key_request_options_set_store_atkey_metadata_initialized(options, true);

  ret = 0;
  goto exit;
exit: { return ret; }
}

void atclient_get_shared_key_request_options_unset_store_atkey_metadata(
    atclient_get_shared_key_request_options *options) {
  /*
   * 1. Validate arguments
   */
  if (options == NULL) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR,
                 "atclient_get_shared_key_request_options_unset_store_atkey_metadata: "
                 "Invalid arguments\n");
    return;
  }

  /*
   * 2. Unset the store atkey metadata
   */
  options->store_atkey_metadata = false;
  atclient_get_shared_key_request_options_set_store_atkey_metadata_initialized(options, false);
}

/*
 * =================
 * 2C. Get PublicKey
 * =================
 */
void atclient_get_public_key_request_options_init(atclient_get_public_key_request_options *options) {
  /*
   * 1. Validate arguments
   */
  if (options == NULL) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR,
                 "atclient_get_public_key_request_options_init: Invalid arguments\n");
    return;
  }

  /*
   * 2. Initialize the options
   */
  memset(options, 0, sizeof(atclient_get_public_key_request_options));
}

void atclient_get_public_key_request_options_free(atclient_get_public_key_request_options *options) {
  /*
   * 1. Validate arguments
   */
  if (options == NULL) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR,
                 "atclient_get_public_key_request_options_free: Invalid arguments\n");
    return;
  }

  /*
   * 2. Free the options
   */
  if (atclient_get_public_key_request_options_is_store_atkey_metadata_initialized(options)) {
    atclient_get_public_key_request_options_unset_store_atkey_metadata(options);
  }

  if (atclient_get_public_key_request_options_is_bypass_cache_initialized(options)) {
    atclient_get_public_key_request_options_unset_bypass_cache(options);
  }
}

bool atclient_get_public_key_request_options_is_bypass_cache_initialized(
    const atclient_get_public_key_request_options *options) {
  /*
   * 1. Validate arguments
   */
  if (options == NULL) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR,
                 "atclient_get_public_key_request_options_is_bypass_cache_initialized: "
                 "Invalid arguments\n");
    return false;
  }

  /*
   * 2. Check if the bypass cache is initialized
   */
  return options->_initialized_fields[ATCLIENT_GET_PUBLIC_KEY_REQUEST_OPTIONS_BYPASS_CACHE_INDEX] &
         ATCLIENT_GET_PUBLIC_KEY_REQUEST_OPTIONS_BYPASS_CACHE_INITIALIZED;
}

static void
atclient_get_public_key_request_options_set_bypass_cache_initialized(atclient_get_public_key_request_options *options,
                                                                     const bool initialized) {
  /*
   * 1. Validate arguments
   */
  if (options == NULL) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR,
                 "atclient_get_public_key_request_options_set_bypass_cache_initialized: "
                 "Invalid arguments\n");
    return;
  }

  /*
   * 2. Set the bypass cache initialized
   */
  if (initialized) {
    options->_initialized_fields[ATCLIENT_GET_PUBLIC_KEY_REQUEST_OPTIONS_BYPASS_CACHE_INDEX] |=
        ATCLIENT_GET_PUBLIC_KEY_REQUEST_OPTIONS_BYPASS_CACHE_INITIALIZED;
  } else {
    options->_initialized_fields[ATCLIENT_GET_PUBLIC_KEY_REQUEST_OPTIONS_BYPASS_CACHE_INDEX] &=
        ~ATCLIENT_GET_PUBLIC_KEY_REQUEST_OPTIONS_BYPASS_CACHE_INITIALIZED;
  }
}

int atclient_get_public_key_request_options_set_bypass_cache(atclient_get_public_key_request_options *options,
                                                             const bool bypass_cache) {
  int ret = 1;

  /*
   * 1. Validate arguments
   */
  if (options == NULL) {
    ret = 1;
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR,
                 "atclient_get_public_key_request_options_set_bypass_cache: "
                 "Invalid arguments\n");
    return ret;
  }

  /*
   * 2. Unset the bypass cache, if necessary
   */
  if (atclient_get_public_key_request_options_is_bypass_cache_initialized(options)) {
    atclient_get_public_key_request_options_unset_bypass_cache(options);
  }

  /*
   * 3. Set the bypass cache
   */
  options->bypass_cache = bypass_cache;
  atclient_get_public_key_request_options_set_bypass_cache_initialized(options, true);

  ret = 0;
  goto exit;
exit: { return ret; }
}

void atclient_get_public_key_request_options_unset_bypass_cache(atclient_get_public_key_request_options *options) {
  /*
   * 1. Validate arguments
   */
  if (options == NULL) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR,
                 "atclient_get_public_key_request_options_unset_bypass_cache: "
                 "Invalid arguments\n");
    return;
  }

  /*
   * 2. Unset the bypass cache
   */
  options->bypass_cache = false;
  atclient_get_public_key_request_options_set_bypass_cache_initialized(options, false);
}

bool atclient_get_public_key_request_options_is_store_atkey_metadata_initialized(
    const atclient_get_public_key_request_options *options) {
  /*
   * 1. Validate arguments
   */
  if (options == NULL) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR,
                 "atclient_get_public_key_request_options_is_store_atkey_metadata_initialized: "
                 "Invalid arguments\n");
    return false;
  }

  /*
   * 2. Check if the store atkey metadata is initialized
   */
  return options->_initialized_fields[ATCLIENT_GET_PUBLIC_KEY_REQUEST_OPTIONS_STORE_ATKEY_METADATA_INDEX] &
         ATCLIENT_GET_PUBLIC_KEY_REQUEST_OPTIONS_STORE_ATKEY_METADATA_INITIALIZED;
}

static void atclient_get_public_key_request_options_set_store_atkey_metadata_initialized(
    atclient_get_public_key_request_options *options, const bool initialized) {
  /*
   * 1. Validate arguments
   */
  if (options == NULL) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR,
                 "atclient_get_public_key_request_options_set_store_atkey_metadata_initialized: "
                 "Invalid arguments\n");
    return;
  }

  /*
   * 2. Set the store atkey metadata initialized
   */
  if (initialized) {
    options->_initialized_fields[ATCLIENT_GET_PUBLIC_KEY_REQUEST_OPTIONS_STORE_ATKEY_METADATA_INDEX] |=
        ATCLIENT_GET_PUBLIC_KEY_REQUEST_OPTIONS_STORE_ATKEY_METADATA_INITIALIZED;
  } else {
    options->_initialized_fields[ATCLIENT_GET_PUBLIC_KEY_REQUEST_OPTIONS_STORE_ATKEY_METADATA_INDEX] &=
        ~ATCLIENT_GET_PUBLIC_KEY_REQUEST_OPTIONS_STORE_ATKEY_METADATA_INITIALIZED;
  }
}

int atclient_get_public_key_request_options_set_store_atkey_metadata(atclient_get_public_key_request_options *options,
                                                                     const bool store_atkey_metadata) {
  int ret = 1;

  /*
   * 1. Validate arguments
   */
  if (options == NULL) {
    ret = 1;
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR,
                 "atclient_get_public_key_request_options_set_store_atkey_metadata: "
                 "Invalid arguments\n");
    goto exit;
  }

  /*
   * 2. Unset the store atkey metadata, if necessary
   */
  if (atclient_get_public_key_request_options_is_store_atkey_metadata_initialized(options)) {
    atclient_get_public_key_request_options_unset_store_atkey_metadata(options);
  }

  /*
   * 3. Set the store atkey metadata
   */
  options->store_atkey_metadata = store_atkey_metadata;
  atclient_get_public_key_request_options_set_store_atkey_metadata_initialized(options, true);

  ret = 0;
  goto exit;
exit: { return ret; }
}

void atclient_get_public_key_request_options_unset_store_atkey_metadata(
    atclient_get_public_key_request_options *options) {
  /*
   * 1. Validate arguments
   */
  if (options == NULL) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR,
                 "atclient_get_public_key_request_options_unset_store_atkey_metadata: "
                 "Invalid arguments\n");
    return;
  }

  /*
   * 2. Unset the store atkey metadata
   */
  options->store_atkey_metadata = false;
  atclient_get_public_key_request_options_set_store_atkey_metadata_initialized(options, false);
}

void atclient_get_atkeys_request_options_init(atclient_get_atkeys_request_options *options) {
  /*
   * 1. Validate arguments
   */
  if (options == NULL) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atclient_get_atkeys_request_options_init: Invalid arguments\n");
    return;
  }

  /*
   * 2. Initialize the options
   */
  memset(options, 0, sizeof(atclient_get_atkeys_request_options));
}

void atclient_get_atkeys_request_options_free(atclient_get_atkeys_request_options *options) {
  /*
   * 1. Validate arguments
   */
  if (options == NULL) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atclient_get_atkeys_request_options_free: Invalid arguments\n");
    return;
  }

  /*
   * 2. Free the options
   */
  if (atclient_get_atkeys_request_options_is_regex_initialized(options)) {
    atclient_get_atkeys_request_options_unset_regex(options);
  }

  if (atclient_get_atkeys_request_options_is_show_hidden_initialized(options)) {
    atclient_get_atkeys_request_options_unset_show_hidden(options);
  }
}

bool atclient_get_atkeys_request_options_is_regex_initialized(const atclient_get_atkeys_request_options *options) {
  /*
   * 1. Validate arguments
   */
  if (options == NULL) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR,
                 "atclient_get_atkeys_request_options_is_regex_initialized: Invalid arguments\n");
    return false;
  }

  /*
   * 2. Check if the regex is initialized
   */
  return options->_initialized_fields[ATCLIENT_GET_ATKEYS_REQUEST_OPTIONS_REGEX_INDEX] &
         ATCLIENT_GET_ATKEYS_REQUEST_OPTIONS_REGEX_INITIALIZED;
}

static void atclient_get_atkeys_request_options_set_regex_initialized(atclient_get_atkeys_request_options *options,
                                                                      const bool initialized) {
  /*
   * 1. Validate arguments
   */
  if (options == NULL) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR,
                 "atclient_get_atkeys_request_options_set_regex_initialized: Invalid arguments\n");
    return;
  }

  /*
   * 2. Set the regex initialized
   */
  if (initialized) {
    options->_initialized_fields[ATCLIENT_GET_ATKEYS_REQUEST_OPTIONS_REGEX_INDEX] |=
        ATCLIENT_GET_ATKEYS_REQUEST_OPTIONS_REGEX_INITIALIZED;
  } else {
    options->_initialized_fields[ATCLIENT_GET_ATKEYS_REQUEST_OPTIONS_REGEX_INDEX] &=
        ~ATCLIENT_GET_ATKEYS_REQUEST_OPTIONS_REGEX_INITIALIZED;
  }
}

int atclient_get_atkeys_request_options_set_regex(atclient_get_atkeys_request_options *options, const char *regex) {
  int ret = 1;

  /*
   * 1. Validate arguments
   */
  if (options == NULL) {
    ret = 1;
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR,
                 "atclient_get_atkeys_request_options_set_regex: Invalid arguments\n");
    return ret;
  }

  if (regex == NULL) {
    ret = 1;
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR,
                 "atclient_get_atkeys_request_options_set_regex: Invalid arguments\n");
    return ret;
  }

  /*
   * 2. Unset the regex, if necessary
   */
  if (atclient_get_atkeys_request_options_is_regex_initialized(options)) {
    atclient_get_atkeys_request_options_unset_regex(options);
  }

  /*
   * 3. Set the regex
   */
  const size_t regex_len = strlen(regex);
  const size_t regex_size = regex_len + 1;
  if ((options->regex = (char *)malloc(sizeof(char) * regex_size)) == NULL) {
    ret = 1;
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR,
                 "atclient_get_atkeys_request_options_set_regex: Failed to allocate memory for regex\n");
    return ret;
  }

  atclient_get_atkeys_request_options_set_regex_initialized(options, true);
  memcpy(options->regex, regex, regex_len);
  options->regex[regex_len] = '\0';

  ret = 0;
  goto exit;
exit: { return ret; }
}

void atclient_get_atkeys_request_options_unset_regex(atclient_get_atkeys_request_options *options) {
  /*
   * 1. Validate arguments
   */
  if (options == NULL) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR,
                 "atclient_get_atkeys_request_options_unset_regex: Invalid arguments\n");
    return;
  }

  /*
   * 2. Unset the regex
   */
  if (atclient_get_atkeys_request_options_is_regex_initialized(options)) {
    free(options->regex);
  }
  options->regex = NULL;
  atclient_get_atkeys_request_options_set_regex_initialized(options, false);
}

bool atclient_get_atkeys_request_options_is_show_hidden_initialized(
    const atclient_get_atkeys_request_options *options) {
  /*
   * 1. Validate arguments
   */
  if (options == NULL) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR,
                 "atclient_get_atkeys_request_options_is_show_hidden_initialized: Invalid arguments\n");
    return false;
  }

  /*
   * 2. Check if the show hidden is initialized
   */
  return options->_initialized_fields[ATCLIENT_GET_ATKEYS_REQUEST_OPTIONS_SHOW_HIDDEN_INDEX] &
         ATCLIENT_GET_ATKEYS_REQUEST_OPTIONS_SHOW_HIDDEN_INITIALIZED;
}

static void
atclient_get_atkeys_request_options_set_show_hidden_initialized(atclient_get_atkeys_request_options *options,
                                                                const bool initialized) {
  /*
   * 1. Validate arguments
   */
  if (options == NULL) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR,
                 "atclient_get_atkeys_request_options_set_show_hidden_initialized: Invalid arguments\n");
    return;
  }

  /*
   * 2. Set the show hidden initialized
   */
  if (initialized) {
    options->_initialized_fields[ATCLIENT_GET_ATKEYS_REQUEST_OPTIONS_SHOW_HIDDEN_INDEX] |=
        ATCLIENT_GET_ATKEYS_REQUEST_OPTIONS_SHOW_HIDDEN_INITIALIZED;
  } else {
    options->_initialized_fields[ATCLIENT_GET_ATKEYS_REQUEST_OPTIONS_SHOW_HIDDEN_INDEX] &=
        ~ATCLIENT_GET_ATKEYS_REQUEST_OPTIONS_SHOW_HIDDEN_INITIALIZED;
  }
}

int atclient_get_atkeys_request_options_set_show_hidden(atclient_get_atkeys_request_options *options,
                                                        const bool show_hidden) {
  int ret = 1;

  /*
   * 1. Validate arguments
   */
  if (options == NULL) {
    ret = 1;
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR,
                 "atclient_get_atkeys_request_options_set_show_hidden: Invalid arguments\n");
    return ret;
  }

  /*
   * 2. Unset the show hidden, if necessary
   */
  if (atclient_get_atkeys_request_options_is_show_hidden_initialized(options)) {
    atclient_get_atkeys_request_options_unset_show_hidden(options);
  }

  /*
   * 3. Set the show hidden
   */
  options->show_hidden = show_hidden;
  atclient_get_atkeys_request_options_set_show_hidden_initialized(options, true);

  ret = 0;
  goto exit;
exit: { return ret; }
}

void atclient_get_atkeys_request_options_unset_show_hidden(atclient_get_atkeys_request_options *options) {
  /*
   * 1. Validate arguments
   */
  if (options == NULL) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR,
                 "atclient_get_atkeys_request_options_unset_show_hidden: Invalid arguments\n");
    return;
  }

  /*
   * 2. Unset the show hidden
   */
  options->show_hidden = false;
  atclient_get_atkeys_request_options_set_show_hidden_initialized(options, false);
}

void atclient_pkam_authenticate_options_init(atclient_pkam_authenticate_options *options) {
  memset(options, 0, sizeof(atclient_pkam_authenticate_options));
  options->at_directory_host = ATCLIENT_PKAM_AUTHENTICATE_DEFAULT_AT_DIRECTORY_HOST;
  options->at_directory_port = ATCLIENT_PKAM_AUTHENTICATE_DEFAULT_AT_DIRECTORY_PORT;
  options->atserver_host = NULL;
  options->atserver_port = 0;
}

void atclient_pkam_authenticate_options_free(atclient_pkam_authenticate_options *options) {
  /*
   * 1. Validate arguments
   */
  if (options == NULL) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atclient_pkam_authenticate_options_free: Invalid arguments\n");
    return;
  }

  /*
   * 2. Free options
   */

  if (atclient_pkam_authenticate_options_is_at_directory_host_initialized(options)) {
    atclient_pkam_authenticate_options_unset_at_directory_host(options);
  }

  if (atclient_pkam_authenticate_options_is_at_directory_port_initialized(options)) {
    atclient_pkam_authenticate_options_unset_at_directory_port(options);
  }

  if (atclient_pkam_authenticate_options_is_atserver_host_initialized(options)) {
    atclient_pkam_authenticate_options_unset_atserver_host(options);
  }

  if (atclient_pkam_authenticate_options_is_atserver_port_initialized(options)) {
    atclient_pkam_authenticate_options_unset_atserver_port(options);
  }
}

bool atclient_pkam_authenticate_options_is_at_directory_host_initialized(
    const atclient_pkam_authenticate_options *options) {
  /*
   * 1. Validate arguments
   */
  if (options == NULL) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR,
                 "atclient_pkam_authenticate_options_is_at_directory_host_initialized: "
                 "Invalid arguments\n");
    return false;
  }

  /*
   * 2. Check if the at directory host is initialized
   */
  return options->_initialized_fields[ATCLIENT_PKAM_AUTHENTICATE_OPTIONS_AT_DIRECTORY_HOST_INDEX] &
         ATCLIENT_PKAM_AUTHENTICATE_OPTIONS_AT_DIRECTORY_HOST_INITIALIZED;
}

bool atclient_pkam_authenticate_options_is_at_directory_port_initialized(
    const atclient_pkam_authenticate_options *options) {
  /*
   * 1. Validate arguments
   */
  if (options == NULL) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR,
                 "atclient_pkam_authenticate_options_is_at_directory_port_initialized: "
                 "Invalid arguments\n");
    return false;
  }

  /*
   * Check if the at directory port is initialized
   */
  return options->_initialized_fields[ATCLIENT_PKAM_AUTHENTICATE_OPTIONS_AT_DIRECTORY_PORT_INDEX] &
         ATCLIENT_PKAM_AUTHENTICATE_OPTIONS_AT_DIRECTORY_PORT_INITIALIZED;
}

bool atclient_pkam_authenticate_options_is_atserver_host_initialized(
    const atclient_pkam_authenticate_options *options) {
  /*
   * 1. Validate arguments
   */
  if (options == NULL) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR,
                 "atclient_pkam_authenticate_options_is_atserver_host_initialized: "
                 "Invalid arguments\n");
    return false;
  }

  /*
   * Check if the atserver host is initialized
   */
  return options->_initialized_fields[ATCLIENT_PKAM_AUTHENTICATE_OPTIONS_ATSERVER_HOST_INDEX] &
         ATCLIENT_PKAM_AUTHENTICATE_OPTIONS_ATSERVER_HOST_INITIALIZED;
}

bool atclient_pkam_authenticate_options_is_atserver_port_initialized(
    const atclient_pkam_authenticate_options *options) {
  /*
   * 1. Validate arguments
   */
  if (options == NULL) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR,
                 "atclient_pkam_authenticate_options_is_atserver_port_initialized: "
                 "Invalid arguments\n");
    return false;
  }

  /*
   * Check if the atserver port is initialized
   */
  return options->_initialized_fields[ATCLIENT_PKAM_AUTHENTICATE_OPTIONS_ATSERVER_PORT_INDEX] &
         ATCLIENT_PKAM_AUTHENTICATE_OPTIONS_ATSERVER_PORT_INITIALIZED;
}

void atclient_pkam_authenticate_options_unset_at_directory_host(atclient_pkam_authenticate_options *options) {
  /*
   * 1. Validate arguments
   */
  if (options == NULL) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR,
                 "atclient_pkam_authenticate_options_unset_at_directory_host: Invalid arguments\n");
    return;
  }

  /*
   * 2. Unsetat directory   */
  if (atclient_pkam_authenticate_options_is_at_directory_host_initialized(options)) {
    free(options->at_directory_host);
  }
  options->at_directory_host = NULL;
}

void atclient_pkam_authenticate_options_unset_at_directory_port(atclient_pkam_authenticate_options *options) {
  /*
   * 1. Validate arguments
   */
  if (options == NULL) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR,
                 "atclient_pkam_authenticate_options_unset_at_directory_port: Invalid arguments\n");
    return;
  }
  options->at_directory_port = 64;
}

void atclient_pkam_authenticate_options_unset_atserver_host(atclient_pkam_authenticate_options *options) {
  /*
   * 1. Validate arguments
   */
  if (options == NULL) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR,
                 "atclient_pkam_authenticate_options_unset_atserver_host: Invalid arguments\n");
    return;
  }

  /*
   * 2. Unset atserver host
   */
  if (atclient_pkam_authenticate_options_is_atserver_host_initialized(options)) {
    free(options->atserver_host);
  }
  options->atserver_host = NULL;
}

void atclient_pkam_authenticate_options_unset_atserver_port(atclient_pkam_authenticate_options *options) {
  /*
   * 1. Validate arguments
   */
  if (options == NULL) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR,
                 "atclient_pkam_authenticate_options_unset_atserver_port: Invalid arguments\n");
    return;
  }
  options->atserver_port = 0;
}

int atclient_pkam_authenticate_options_set_at_directory_host(atclient_pkam_authenticate_options *options,
                                                             char *at_directory_host) {
  int ret = 1;

  /*
   * 1. Validate arguments
   */
  if (options == NULL) {
    ret = 1;
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR,
                 "atclient_pkam_authenticate_options_set_at_directory_host: Invalid arguments\n");
    return ret;
  }

  /*
   * 2. Unset at directory host, if initialized
   */
  if (atclient_pkam_authenticate_options_is_at_directory_host_initialized(options)) {
    atclient_pkam_authenticate_options_unset_at_directory_host(options);
  }

  /*
   * 3. Set at directory host
   */
  options->at_directory_host = at_directory_host;
  ret = 0;
  goto exit;
exit: { return ret; }
}

int atclient_pkam_authenticate_options_set_at_directory_port(atclient_pkam_authenticate_options *options,
                                                             int at_directory_port) {
  int ret = 1;

  /*
   * 1. Validate arguments
   */
  if (options == NULL) {
    ret = 1;
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR,
                 "atclient_pkam_authenticate_options_set_at_directory_port: Invalid arguments\n");
    return ret;
  }

  /*
   * 2. Unset at directory port, if initialized
   */
  if (atclient_pkam_authenticate_options_is_at_directory_port_initialized(options)) {
    atclient_pkam_authenticate_options_unset_at_directory_host(options);
  }

  /*
   * 3. Set at directory port
   */
  options->at_directory_port = at_directory_port;
  ret = 0;
  goto exit;
exit: { return ret; }
}

int atclient_pkam_authenticate_options_set_atserver_host(atclient_pkam_authenticate_options *options,
                                                         char *atserver_host) {
  int ret = 1;

  /*
   * 1. Validate arguments
   */
  if (options == NULL) {
    ret = 1;
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR,
                 "atclient_pkam_authenticate_options_set_atserver_host: Invalid arguments\n");
    return ret;
  }

  /*
   * 2. Unset the atserver host, if initialized
   */
  if (atclient_pkam_authenticate_options_is_atserver_host_initialized(options)) {
    atclient_pkam_authenticate_options_unset_atserver_host(options);
  }

  /*
   * 3. Set atserver host
   */
  options->atserver_host = atserver_host;

  ret = 0;
  goto exit;

exit: { return ret; }
}

int atclient_pkam_authenticate_options_set_atserver_port(atclient_pkam_authenticate_options *options,
                                                         int atserver_port) {
  int ret = 1;

  /*
   * 1. Validate arguments
   */
  if (options == NULL) {
    ret = 1;
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR,
                 "atclient_pkam_authenticate_options_set_atserver_port: Invalid arguments\n");
    return ret;
  }

  /*
   * 2. Unset the atserver port, if initialized
   */
  if (atclient_pkam_authenticate_options_is_atserver_port_initialized(options)) {
    atclient_pkam_authenticate_options_unset_atserver_host(options);
  }

  /*
   * 3. Set atserver port
   */
  options->atserver_port = atserver_port;

  ret = 0;
  goto exit;

exit: { return ret; }
}