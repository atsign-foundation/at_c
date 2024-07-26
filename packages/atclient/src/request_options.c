#include <atchops/aes.h>
#include <atclient/request_options.h>
#include <atlogger/atlogger.h>
#include <stdbool.h>
#include <stddef.h>
#include <string.h>

#define TAG "request_options"

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
  if (atclient_put_self_key_request_options_is_shared_encryption_key_initialized(options)) {
    atclient_put_self_key_request_options_unset_shared_encryption_key(options);
  }
}

bool atclient_put_self_key_request_options_is_shared_encryption_key_initialized(
    const atclient_put_self_key_request_options *options) {
  /*
   * 1. Validate arguments
   */
  if (options == NULL) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR,
                 "atclient_put_self_key_request_options_is_shared_encryption_key_initialized: Invalid arguments\n");
    return false;
  }

  /*
   * 2. Check if the shared encryption key is initialized
   */
  return options->_initialized_fields[ATCLIENT_PUT_SELF_KEY_REQUEST_OPTIONS_SHARED_ENCRYPTION_KEY_INDEX] &
         ATCLIENT_PUT_SELF_KEY_REQUEST_OPTIONS_SHARED_ENCRYPTION_KEY_INITIALIZED;
}
void atclient_put_self_key_request_options_set_shared_encryption_key_initialized(
    atclient_put_self_key_request_options *options, const bool initialized) {
  /*
   * 1. Validate arguments
   */
  if (options == NULL) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR,
                 "atclient_put_self_key_request_options_set_shared_encryption_key_initialized: "
                 "Invalid arguments\n");
    return;
  }

  /*
   * 2. Set the shared encryption key initialized
   */
  if (initialized) {
    options->_initialized_fields[ATCLIENT_PUT_SELF_KEY_REQUEST_OPTIONS_SHARED_ENCRYPTION_KEY_INDEX] |=
        ATCLIENT_PUT_SELF_KEY_REQUEST_OPTIONS_SHARED_ENCRYPTION_KEY_INITIALIZED;
  } else {
    options->_initialized_fields[ATCLIENT_PUT_SELF_KEY_REQUEST_OPTIONS_SHARED_ENCRYPTION_KEY_INDEX] &=
        ~ATCLIENT_PUT_SELF_KEY_REQUEST_OPTIONS_SHARED_ENCRYPTION_KEY_INITIALIZED;
  }
}

int atclient_put_self_key_request_options_set_shared_encryption_key(atclient_put_self_key_request_options *options,
                                                                    const unsigned char *shared_encryption_key) {
  /*
   * 1. Validate arguments
   */
  int ret = 1;
  if (options == NULL || shared_encryption_key == NULL) {
    ret = 1;
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR,
                 "atclient_put_self_key_request_options_set_shared_encryption_key: "
                 "Invalid arguments\n");
    goto exit;
  }

  /*
   * 2. Unset the shared encryption key, if necessary
   */
  if (atclient_put_self_key_request_options_is_shared_encryption_key_initialized(options)) {
    atclient_put_self_key_request_options_unset_shared_encryption_key(options);
  }

  /*
   * 3. Set the shared encryption key
   */
  const size_t shared_encryption_key_size = ATCHOPS_AES_256 / 8;
  if ((options->shared_encryption_key = (unsigned char *)malloc(sizeof(unsigned char) * shared_encryption_key_size)) ==
      NULL) {
    ret = 1;
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR,
                 "atclient_put_self_key_request_options_set_shared_encryption_key: "
                 "Failed to allocate memory for shared encryption key\n");
    goto exit;
  }

  atclient_put_self_key_request_options_set_shared_encryption_key_initialized(options, true);
  memcpy(options->shared_encryption_key, shared_encryption_key, shared_encryption_key_size);

  ret = 0;
  goto exit;
exit: { return ret; }
}

void atclient_put_self_key_request_options_unset_shared_encryption_key(atclient_put_self_key_request_options *options) {
  /*
   * 1. Validate arguments
   */
  if (options == NULL) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR,
                 "atclient_put_self_key_request_options_unset_shared_encryption_key: Invalid arguments\n");
    return;
  }

  /*
   * 2. Unset the shared encryption key
   */
  if (atclient_put_self_key_request_options_is_shared_encryption_key_initialized(options)) {
    free(options->shared_encryption_key);
  }
  options->shared_encryption_key = NULL;
  atclient_put_self_key_request_options_set_shared_encryption_key_initialized(options, false);
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

  if (atclient_put_shared_key_request_options_is_bypass_cache_initialized(options)) {
    atclient_put_shared_key_request_options_unset_bypass_cache(options);
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

void atclient_put_shared_key_request_options_set_shared_encryption_key_initialized(
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

bool atclient_put_shared_key_request_options_is_bypass_cache_initialized(
    const atclient_put_shared_key_request_options *options) {
  /*
   * 1. Validate arguments
   */
  if (options == NULL) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR,
                 "atclient_put_shared_key_request_options_is_bypass_cache_initialized: "
                 "Invalid arguments\n");
    return false;
  }

  /*
   * 2. Check if the bypass cache is initialized
   */
  return options->_initialized_fields[ATCLIENT_PUT_SHARED_KEY_REQUEST_OPTIONS_BYPASS_CACHE_INDEX] &
         ATCLIENT_PUT_SHARED_KEY_REQUEST_OPTIONS_BYPASS_CACHE_INITIALIZED;
}

void atclient_put_shared_key_request_options_set_bypass_cache_initialized(
    atclient_put_shared_key_request_options *options, const bool initialized) {
  /*
   * 1. Validate arguments
   */

  if (options == NULL) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR,
                 "atclient_put_shared_key_request_options_set_bypass_cache_initialized: "
                 "Invalid arguments\n");
    return;
  }

  /*
   * 2. Set the bypass cache initialized
   */
  if (initialized) {
    options->_initialized_fields[ATCLIENT_PUT_SHARED_KEY_REQUEST_OPTIONS_BYPASS_CACHE_INDEX] |=
        ATCLIENT_PUT_SHARED_KEY_REQUEST_OPTIONS_BYPASS_CACHE_INITIALIZED;
  } else {
    options->_initialized_fields[ATCLIENT_PUT_SHARED_KEY_REQUEST_OPTIONS_BYPASS_CACHE_INDEX] &=
        ~ATCLIENT_PUT_SHARED_KEY_REQUEST_OPTIONS_BYPASS_CACHE_INITIALIZED;
  }
}

int atclient_put_shared_key_request_options_set_bypass_cache(atclient_put_shared_key_request_options *options,
                                                             const bool bypass_cache) {
  int ret = 1;
  /*
   * 1. Validate arguments
   */
  if (options == NULL) {
    ret = 1;
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR,
                 "atclient_put_shared_key_request_options_set_bypass_cache: "
                 "Invalid arguments\n");
    goto exit;
  }

  /*
   * 2. Unset the bypass cache, if necessary
   */
  if (atclient_put_shared_key_request_options_is_bypass_cache_initialized(options)) {
    atclient_put_shared_key_request_options_unset_bypass_cache(options);
  }

  /*
   * 3. Set the bypass cache
   */
  options->bypass_cache = bypass_cache;
  atclient_put_shared_key_request_options_set_bypass_cache_initialized(options, true);

  ret = 0;
  goto exit;
exit: { return ret; }
}

void atclient_put_shared_key_request_options_unset_bypass_cache(atclient_put_shared_key_request_options *options) {
  /*
   * 1. Validate arguments
   */
  if (options == NULL) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR,
                 "atclient_put_shared_key_request_options_unset_bypass_cache: "
                 "Invalid arguments\n");
    return;
  }

  /*
   * 2. Unset the bypass cache
   */
  options->bypass_cache = false;
  atclient_put_shared_key_request_options_set_bypass_cache_initialized(options, false);
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
  if (atclient_put_public_key_request_options_is_bypass_cache_initialized(options)) {
    atclient_put_public_key_request_options_unset_bypass_cache(options);
  }
}

bool atclient_put_public_key_request_options_is_bypass_cache_initialized(
    const atclient_put_public_key_request_options *options) {
  /*
   * 1. Validate arguments
   */
  if (options == NULL) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR,
                 "atclient_put_public_key_request_options_is_bypass_cache_initialized: "
                 "Invalid arguments\n");
    return false;
  }

  /*
   * 2. Check if the bypass cache is initialized
   */
  return options->_initialized_fields[ATCLIENT_PUT_PUBLIC_KEY_REQUEST_OPTIONS_BYPASS_CACHE_INDEX] &
         ATCLIENT_PUT_PUBLIC_KEY_REQUEST_OPTIONS_BYPASS_CACHE_INITIALIZED;
}

void atclient_put_public_key_request_options_set_bypass_cache_initialized(
    atclient_put_public_key_request_options *options, const bool initialized) {
  /*
   * 1. Validate arguments
   */
  if (options == NULL) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR,
                 "atclient_put_public_key_request_options_set_bypass_cache_initialized: "
                 "Invalid arguments\n");
    return;
  }

  /*
   * 2. Set the bypass cache initialized
   */
  if (initialized) {
    options->_initialized_fields[ATCLIENT_PUT_PUBLIC_KEY_REQUEST_OPTIONS_BYPASS_CACHE_INDEX] |=
        ATCLIENT_PUT_PUBLIC_KEY_REQUEST_OPTIONS_BYPASS_CACHE_INITIALIZED;
  } else {
    options->_initialized_fields[ATCLIENT_PUT_PUBLIC_KEY_REQUEST_OPTIONS_BYPASS_CACHE_INDEX] &=
        ~ATCLIENT_PUT_PUBLIC_KEY_REQUEST_OPTIONS_BYPASS_CACHE_INITIALIZED;
  }
}

int atclient_put_public_key_request_options_set_bypass_cache(atclient_put_public_key_request_options *options,
                                                             const bool bypass_cache) {
  int ret = 1;

  /*
   * 1. Validate arguments
   */
  if (options == NULL) {
    ret = 1;
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR,
                 "atclient_put_public_key_request_options_set_bypass_cache: "
                 "Invalid arguments\n");
    goto exit;
  }

  /*
   * 2. Unset the bypass cache, if necessary
   */
  if (atclient_put_public_key_request_options_is_bypass_cache_initialized(options)) {
    atclient_put_public_key_request_options_unset_bypass_cache(options);
  }

  /*
   * 3. Set the bypass cache
   */
  options->bypass_cache = bypass_cache;
  atclient_put_public_key_request_options_set_bypass_cache_initialized(options, true);

  ret = 0;
  goto exit;
exit: { return ret; }
}

void atclient_put_public_key_request_options_unset_bypass_cache(atclient_put_public_key_request_options *options) {
  /*
   * 1. Validate arguments
   */
  if (options == NULL) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR,
                 "atclient_put_public_key_request_options_unset_bypass_cache: "
                 "Invalid arguments\n");
    return;
  }

  /*
   * 2. Unset the bypass cache
   */
  options->bypass_cache = false;
  atclient_put_public_key_request_options_set_bypass_cache_initialized(options, false);
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
  if (atclient_get_self_key_request_options_is_shared_encryption_key_initialized(options)) {
    atclient_get_self_key_request_options_unset_shared_encryption_key(options);
  }
}

bool atclient_get_self_key_request_options_is_shared_encryption_key_initialized(
    const atclient_get_self_key_request_options *options) {
  /*
   * 1. Validate arguments
   */
  if (options == NULL) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR,
                 "atclient_get_self_key_request_options_is_shared_encryption_key_initialized: Invalid arguments\n");
    return false;
  }

  /*
   * 2. Check if the shared encryption key is initialized
   */
  return options->_initialized_fields[ATCLIENT_GET_SELF_KEY_REQUEST_OPTIONS_SHARED_ENCRYPTION_KEY_INDEX] &
         ATCLIENT_GET_SELF_KEY_REQUEST_OPTIONS_SHARED_ENCRYPTION_KEY_INITIALIZED;
}

void atclient_get_self_key_request_options_set_shared_encryption_key_initialized(
    atclient_get_self_key_request_options *options, const bool initialized) {
  /*
   * 1. Validate arguments
   */
  if (options == NULL) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR,
                 "atclient_get_self_key_request_options_set_shared_encryption_key_initialized: Invalid arguments\n");
    return;
  }

  /*
   * 2. Set the shared encryption key initialized
   */
  if (initialized) {
    options->_initialized_fields[ATCLIENT_GET_SELF_KEY_REQUEST_OPTIONS_SHARED_ENCRYPTION_KEY_INDEX] |=
        ATCLIENT_GET_SELF_KEY_REQUEST_OPTIONS_SHARED_ENCRYPTION_KEY_INITIALIZED;
  } else {
    options->_initialized_fields[ATCLIENT_GET_SELF_KEY_REQUEST_OPTIONS_SHARED_ENCRYPTION_KEY_INDEX] &=
        ~ATCLIENT_GET_SELF_KEY_REQUEST_OPTIONS_SHARED_ENCRYPTION_KEY_INITIALIZED;
  }
}

int atclient_get_self_key_request_options_set_shared_encryption_key(atclient_get_self_key_request_options *options,
                                                                    const unsigned char *shared_encryption_key) {
  int ret = 1;

  /*
   * 1. Validate arguments
   */
  if (options == NULL) {
    ret = 1;
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR,
                 "atclient_get_self_key_request_options_set_shared_encryption_key: Invalid arguments\n");
    goto exit;
  }

  if (shared_encryption_key == NULL) {
    ret = 1;
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR,
                 "atclient_get_self_key_request_options_set_shared_encryption_key: Invalid arguments\n");
    goto exit;
  }

  /*
   * 2. Unset the shared encryption key, if necessary
   */
  if (atclient_get_self_key_request_options_is_shared_encryption_key_initialized(options)) {
    atclient_get_self_key_request_options_unset_shared_encryption_key(options);
  }

  /*
   * 3. Set the shared encryption key
   */
  const size_t shared_encryption_key_size = ATCHOPS_AES_256 / 8;
  if ((options->shared_encryption_key = (unsigned char *)malloc(sizeof(unsigned char) * shared_encryption_key_size)) ==
      NULL) {
    ret = 1;
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR,
                 "atclient_get_self_key_request_options_set_shared_encryption_key: Failed to allocate memory for "
                 "shared encryption key\n");
    goto exit;
  }

  atclient_get_self_key_request_options_set_shared_encryption_key_initialized(options, true);
  memcpy(options->shared_encryption_key, shared_encryption_key, shared_encryption_key_size);

  ret = 0;
  goto exit;
exit: { return ret; }
}

void atclient_get_self_key_request_options_unset_shared_encryption_key(atclient_get_self_key_request_options *options) {
  /*
   * 1. Validate arguments
   */
  if (options == NULL) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR,
                 "atclient_get_self_key_request_options_unset_shared_encryption_key: Invalid arguments\n");
    return;
  }

  /*
   * 2. Unset the shared encryption key
   */
  if (atclient_get_self_key_request_options_is_shared_encryption_key_initialized(options)) {
    free(options->shared_encryption_key);
  }
  options->shared_encryption_key = NULL;
  atclient_get_self_key_request_options_set_shared_encryption_key_initialized(options, false);
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
void atclient_get_shared_key_request_options_set_shared_encryption_key_initialized(
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

void atclient_get_public_key_request_options_set_store_atkey_metadata_initialized(
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
