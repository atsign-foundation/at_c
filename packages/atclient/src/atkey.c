#include "atclient/atkey.h"
#include "atclient/atsign.h"
#include "atclient/constants.h"
#include "atclient/metadata.h"
#include "atclient/stringutils.h"
#include "atlogger/atlogger.h"
#include <stdbool.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define TAG "atkey"

void atclient_atkey_init(atclient_atkey *atkey) {
  memset(atkey, 0, sizeof(atclient_atkey));
  atkey->key = NULL;
  atkey->shared_by = NULL;
  atkey->shared_with = NULL;
  atkey->namespace_str = NULL;
  memset(atkey->_initialized_fields, 0, sizeof(atkey->_initialized_fields));
  atclient_atkey_metadata_init(&(atkey->metadata));
}

int atclient_atkey_clone(atclient_atkey *dst, const atclient_atkey *src) {
  int ret = 1;
  if (dst == NULL) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "dst is NULL\n");
    goto exit;
  }
  if (src == NULL) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "src is NULL\n");
    goto exit;
  }
  if (atclient_atkey_is_key_initialized(src)) {
    if ((ret = atclient_atkey_set_key(dst, src->key)) != 0) {
      atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atclient_atkey_set_key failed\n");
      goto exit;
    }
  }
  if (atclient_atkey_is_shared_by_initialized(src)) {
    if ((ret = atclient_atkey_set_shared_by(dst, src->shared_by)) != 0) {
      atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atclient_atkey_set_shared_by failed\n");
      goto exit;
    }
  }
  if (atclient_atkey_is_shared_with_initialized(src)) {
    if ((ret = atclient_atkey_set_shared_with(dst, src->shared_with)) != 0) {
      atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atclient_atkey_set_shared_with failed\n");
      goto exit;
    }
  }
  if (atclient_atkey_is_namespacestr_initialized(src)) {
    if ((ret = atclient_atkey_set_namespace_str(dst, src->namespace_str)) != 0) {
      atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atclient_atkey_set_namespace_str failed\n");
      goto exit;
    }
  }
  if ((ret = atclient_atkey_metadata_clone(&(dst->metadata), &(src->metadata))) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atclient_atkey_metadata_clone failed\n");
    goto exit;
  }
  ret = 0;
  goto exit;
exit: {
  return ret;
}
}

void atclient_atkey_free(atclient_atkey *atkey) {
  atclient_atkey_metadata_free(&(atkey->metadata));
  memset(atkey, 0, sizeof(atclient_atkey));
}

size_t atclient_atkey_strlen(const atclient_atkey *atkey) {
  if (atkey == NULL) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atkey is NULL\n");
    return -1;
  }
  if (!atclient_atkey_is_key_initialized(atkey) || !atclient_atkey_is_shared_by_initialized(atkey)) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atkey->key or atkey->shared_by is not initialized\n");
    return -1;
  }
  if (strlen(atkey->key) <= 0 || strlen(atkey->shared_by) <= 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atkey->key or atkey->shared_by is empty\n");
    return -1;
  }
  atclient_atkey_type type = atclient_atkey_get_type(atkey);
  if (type == ATCLIENT_ATKEY_TYPE_UNKNOWN) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atkey type is unknown\n");
    return -1;
  }
  size_t len = 0;
  if (atclient_atkey_metadata_is_is_cached_initialized(&(atkey->metadata)) && atkey->metadata.is_cached) {
    len += strlen("cached:");
  }
  if (atclient_atkey_metadata_is_is_public_initialized(&(atkey->metadata)) && atkey->metadata.is_public) {
    len += strlen("public:");
  }
  if (type == ATCLIENT_ATKEY_TYPE_SHARED_KEY && atclient_atkey_is_shared_with_initialized(atkey)) {
    len += strlen(atkey->shared_with) + strlen(":");
  }
  len += strlen(atkey->key);
  if (atclient_atkey_is_namespacestr_initialized(atkey) && strlen(atkey->namespace_str) > 0) {
    len += strlen(".") + strlen(atkey->namespace_str);
  }
  len += strlen(atkey->shared_by);
  return len;
}

int atclient_atkey_from_string(atclient_atkey *atkey, const char *atkeystr) {
  // 6 scenarios:
  // 1. PublicKey:            "public:name.wavi@smoothalligator"
  //      name == "name"
  //      shared_by = "smoothalligator"
  //      shared_with = NULL
  //      namespace = "wavi"
  //      type = "public"
  //      cached = false
  // 2. PublicKey (cached):   "cached:public:name.wavi@smoothalligator"
  //      name == "name"
  //      shared_by = "smoothalligator"
  //      shared_with = NULL
  //      namespace = "wavi"
  //      type = "public"
  //      cached = true
  // 3. SharedKey:            "@foo:name.wavi@bar"
  //      name == "name"
  //      shared_by = "bar"
  //      shared_with = "foo"
  //      namespace = "wavi"
  //      cached = false
  // 4. SharedKey (cached):   "cached:@bar:name.wavi@foo"
  //      name == "name"
  //      shared_by = "foo"
  //      shared_with = "bar"
  //      namespace = "wavi"
  //      cached = true
  // 5. SelfKey:              "name.wavi@smoothalligator"
  //      name == "name"
  //      shared_by = "smoothalligator"
  //      shared_with = NULL
  //      namespace = "wavi"
  //      cached = false
  // more scenarios
  // 6. No Namespace, SelfKey:
  // "name@smoothalligator"
  //      name == "name"
  //      shared_by = "smoothalligator"
  //      shared_with = NULL
  //      namespace = NULL
  //      cached = false
  int ret = 1;

  /*
   * 1. Validate Arguments
   */
  // TODO

  /*
   * 2. Variables
   */

  char *shared_by_with_at = NULL;
  char *save_ptr;

  const size_t composite_size = ATCLIENT_ATKEY_COMPOSITE_LEN + 1;
  char composite[composite_size]; // holds {key}.{namespace}
  memset(composite, 0, sizeof(char) * composite_size);

  char *copy = NULL;

  /*
   * 3.
   */
  if ((copy = strdup(atkeystr)) == NULL) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "strdndup failed\n");
    goto exit;
  }

  char *token = strtok_r(copy, ":", &save_ptr);
  if (token == NULL) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "tokens[0] is NULL\n");
    ret = 1;
    goto exit;
  }
  size_t tokenlen = strlen(token);
  // check if cached
  if (strncmp(token, "cached", strlen("cached")) == 0) {
    atclient_atkey_metadata_set_is_cached(&(atkey->metadata), true);
    token = strtok_r(NULL, ":", &save_ptr);
    if (token == NULL) {
      atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "tokens[1] is NULL\n");
      ret = 1;
      goto exit;
    }
  }

  if (atclient_stringutils_starts_with(token, "public")) {
    // it is a public key
    atclient_atkey_metadata_set_is_public(&(atkey->metadata), true);
    // shift tokens array to the left
    token = strtok_r(NULL, ":", &save_ptr);
    if (token == NULL) {
      atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "token is NULL. %s atkey is probably incomplete\n", atkeystr);
      ret = 1;
      goto exit;
    }
  } else if (atclient_stringutils_starts_with(token, "@")) {
    // it is a shared key
    // set shared_with
    if ((ret = atclient_atkey_set_shared_with(atkey, token)) != 0) {
      atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atclient_atkey_set_shared_with failed\n");
      goto exit;
    }
    token = strtok_r(NULL, ":", &save_ptr);
    if (token == NULL) {
      ret = 1;
      atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "token is NULL. %s atkey is probably incomplete\n", atkeystr);
      goto exit;
    }
  } else if (atclient_stringutils_starts_with(token, "_")) {
    // it is an internal key
  } else {
    // it is a self key
  }

  // set atkey->name
  token = strtok_r(token, "@", &save_ptr);
  if (token == NULL) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "token is NULL. %s atkey is probably incomplete\n", atkeystr);
    ret = 1;
    goto exit;
  }
  tokenlen = strlen(token);

  memcpy(composite, token, tokenlen);

  char *check = strchr(composite, '.');
  if (check != NULL && *(check + 1) != '\0') { // there is a namespace
    char *saveptr2;

    char *key = strtok_r(composite, ".", &saveptr2);
    if (key == NULL) {
      atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "key is NULL. %s atkey is probably incomplete\n", atkeystr);
      ret = 1;
      goto exit;
    }
    if ((ret = atclient_atkey_set_key(atkey, key)) != 0) {
      atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atclient_atkey_set_key failed\n");
      goto exit;
    }

    char *namespace_str = strtok_r(NULL, "", &saveptr2);
    if (namespace_str == NULL) {
      ret = 1;
      atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "namespace_str is NULL. %s atkey is probably incomplete\n",
                   atkeystr);
      goto exit;
    }
    if ((ret = atclient_atkey_set_namespace_str(atkey, namespace_str)) != 0) {
      atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atclient_atkey_set_namespace_str failed\n");
      goto exit;
    }
  } else { // there is no namespace
    if ((ret = atclient_atkey_set_key(atkey, composite)) != 0) {
      atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atclient_atkey_set_key failed\n");
      goto exit;
    }
  }

  // set atkey->shared_by
  token = strtok_r(NULL, "", &save_ptr);
  if (token == NULL) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "token is NULL. %s atkey is probably incomplete\n", atkeystr);
    ret = 1;
    goto exit;
  }
  tokenlen = strlen(token);

  if ((ret = atclient_stringutils_atsign_with_at(token, &shared_by_with_at)) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atclient_stringutils_atsign_with_at failed\n");
    goto exit;
  }

  if ((ret = atclient_atkey_set_shared_by(atkey, shared_by_with_at)) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atclient_atkey_set_shared_by failed\n");
    goto exit;
  }

  ret = 0;
  goto exit;
exit: {
  free(copy);
  free(shared_by_with_at);
  return ret;
}
}

int atclient_atkey_to_string(const atclient_atkey *atkey, char **atkeystr) {
  int ret = 1;

  if (atkey == NULL) {
    ret = 1;
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atkey is NULL\n");
    return ret;
  }

  if (atkeystr == NULL) {
    ret = 1;
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "**atkeystr is NULL\n");
    return ret;
  }

  atclient_atkey_type atkey_type = atclient_atkey_get_type(atkey);

  if (atkey_type == ATCLIENT_ATKEY_TYPE_UNKNOWN) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atkey_type is unknown\n");
    return ret;
  }

  if (!atclient_atkey_is_shared_by_initialized(atkey) || strlen(atkey->shared_by) <= 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR,
                 "atkey->shared_by is not initialized or strlen(atkey->shared_by) <= 0. AtKey is incomplete.\n");
    return ret;
  }

  if (!atclient_atkey_is_key_initialized(atkey) || strlen(atkey->key) <= 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR,
                 "atkey->key is not initialized or strlen(atkey->key) <= 0. AtKey is incomplete.\n");
    return ret;
  }

  size_t index_pos = 0;
  const size_t atkey_str_size = atclient_atkey_strlen(atkey) + 1;
  if ((*atkeystr = (char *)malloc(sizeof(char) * atkey_str_size)) == NULL) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "malloc failed\n");
    goto error_exit;
  }
  memset(*atkeystr, 0, sizeof(char) * atkey_str_size);

  if (atclient_atkey_metadata_is_is_cached_initialized(&(atkey->metadata)) && atkey->metadata.is_cached) {
    snprintf(*atkeystr + index_pos, atkey_str_size - index_pos, "cached:");
    index_pos += strlen("cached:");
  }

  if (atkey_type == ATCLIENT_ATKEY_TYPE_PUBLIC_KEY) {
    if (!atclient_atkey_metadata_is_is_public_initialized(&(atkey->metadata)) || !atkey->metadata.is_public) {
      atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_WARN,
                   "atkey's metadata is_public is either not initialized or false, even though it was deemed a "
                   "ATCLIENT_ATKEY_TYPE_PUBLIC_KEY by atclient_atkey_get_type\n");
    }
    snprintf(*atkeystr + index_pos, atkey_str_size - index_pos, "public:");
    index_pos += strlen("public:");
  } else if (atkey_type == ATCLIENT_ATKEY_TYPE_SHARED_KEY) {
    if (!atclient_atkey_is_shared_with_initialized(atkey)) {
      atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_WARN,
                   "atkey's shared_with is not initialized, even though it was deemed a ATCLIENT_ATKEY_TYPE_SHARED_KEY by "
                   "atclient_atkey_get_type\n");
    }
    snprintf(*atkeystr + index_pos, atkey_str_size - index_pos, "%s:", atkey->shared_with);
    index_pos += strlen(atkey->shared_with) + strlen(":");
  }

  snprintf(*atkeystr + index_pos, atkey_str_size - index_pos, "%s", atkey->key);
  index_pos += strlen(atkey->key);

  if (atclient_atkey_is_namespacestr_initialized(atkey) && strlen(atkey->namespace_str) > 0) {
    snprintf(*atkeystr + index_pos, atkey_str_size - index_pos, ".%s", atkey->namespace_str);
    index_pos += strlen(".") + strlen(atkey->namespace_str);
  }

  snprintf(*atkeystr + index_pos, atkey_str_size - index_pos, "%s", atkey->shared_by);
  index_pos += strlen(atkey->shared_by);

  if (index_pos != atkey_str_size - 1) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_WARN,
                 "index_pos != atkey_str_size - 1 (%d != %d - 1). The predicted `atkey_str_size` variable was not "
                 "evaluated correctly.\n",
                 index_pos, atkey_str_size);
  }

  ret = 0;
  goto exit;
error_exit: {
  free(*atkeystr);
  goto exit;
}
exit: { return ret; }
}

bool atclient_atkey_is_key_initialized(const atclient_atkey *atkey) {
  return (atkey->_initialized_fields[ATCLIENT_ATKEY_KEY_INDEX] & ATCLIENT_ATKEY_KEY_INITIALIZED);
}

bool atclient_atkey_is_namespacestr_initialized(const atclient_atkey *atkey) {
  return (atkey->_initialized_fields[ATCLIENT_ATKEY_NAMESPACE_STR_INDEX] & ATCLIENT_ATKEY_NAMESPACE_STR_INITIALIZED);
}

bool atclient_atkey_is_shared_by_initialized(const atclient_atkey *atkey) {
  return (atkey->_initialized_fields[ATCLIENT_ATKEY_SHARED_BY_INDEX] & ATCLIENT_ATKEY_SHARED_BY_INITIALIZED);
}

bool atclient_atkey_is_shared_with_initialized(const atclient_atkey *atkey) {
  return (atkey->_initialized_fields[ATCLIENT_ATKEY_SHARED_WITH_INDEX] & ATCLIENT_ATKEY_SHARED_WITH_INITIALIZED);
}

int atclient_atkey_set_key(atclient_atkey *atkey, const char *key) {
  int ret = 1;
  if (atkey == NULL) {
    ret = 1;
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atkey is NULL. This is a required argument.\n");
    goto exit;
  }
  if (key == NULL) {
    ret = 1;
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "key is NULL. This is a required argument.\n");
    goto exit;
  }
  if (atclient_atkey_is_key_initialized(atkey)) {
    free(atkey->key);
    atkey->key = NULL;
    atkey->_initialized_fields[ATCLIENT_ATKEY_KEY_INDEX] &= ~ATCLIENT_ATKEY_KEY_INITIALIZED;
  }
  atkey->key = strdup(key);
  if (atkey->key == NULL) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "strdup failed\n");
    ret = 1;
    goto exit;
  }
  atkey->_initialized_fields[ATCLIENT_ATKEY_KEY_INDEX] |= ATCLIENT_ATKEY_KEY_INITIALIZED;
  ret = 0;
  goto exit;
exit: { return ret; }
}

int atclient_atkey_set_namespace_str(atclient_atkey *atkey, const char *namespace_str) {
  int ret = 1;
  if (atkey == NULL) {
    ret = 1;
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atkey is NULL. This is a required argument.\n");
    goto exit;
  }
  if (namespace_str == NULL) {
    ret = 1;
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "namespace_str is NULL. This is a required argument.\n");
    goto exit;
  }
  if (atclient_atkey_is_namespacestr_initialized(atkey)) {
    free(atkey->namespace_str);
    atkey->namespace_str = NULL;
    atkey->_initialized_fields[ATCLIENT_ATKEY_NAMESPACE_STR_INDEX] &= ~ATCLIENT_ATKEY_NAMESPACE_STR_INITIALIZED;
  }
  atkey->namespace_str = strdup(namespace_str);
  if (atkey->namespace_str == NULL) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "strdup failed\n");
    ret = 1;
    goto exit;
  }
  atkey->_initialized_fields[ATCLIENT_ATKEY_NAMESPACE_STR_INDEX] |= ATCLIENT_ATKEY_NAMESPACE_STR_INITIALIZED;
  ret = 0;
  goto exit;
exit: { return ret; }
}

int atclient_atkey_set_shared_by(atclient_atkey *atkey, const char *shared_by) {
  int ret = 1;
  if (atkey == NULL) {
    ret = 1;
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atkey is NULL. This is a required argument.\n");
    goto exit;
  }
  if (shared_by == NULL) {
    ret = 1;
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "shared_by is NULL. This is a required argument.\n");
    goto exit;
  }
  if (atclient_atkey_is_shared_by_initialized(atkey)) {
    free(atkey->shared_by);
    atkey->shared_by = NULL;
    atkey->_initialized_fields[ATCLIENT_ATKEY_SHARED_BY_INDEX] &= ~ATCLIENT_ATKEY_SHARED_BY_INITIALIZED;
  }
  atkey->shared_by = strdup(shared_by);
  if (atkey->shared_by == NULL) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "strdup failed\n");
    ret = 1;
    goto exit;
  }
  atkey->_initialized_fields[ATCLIENT_ATKEY_SHARED_BY_INDEX] |= ATCLIENT_ATKEY_SHARED_BY_INITIALIZED;
  ret = 0;
  goto exit;
exit: { return ret; }
}

int atclient_atkey_set_shared_with(atclient_atkey *atkey, const char *shared_with) {
  int ret = 1;
  if (atkey == NULL) {
    ret = 1;
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atkey is NULL. This is a required argument.\n");
    goto exit;
  }
  if (shared_with == NULL) {
    ret = 1;
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "shared_with is NULL. This is a required argument.\n");
    goto exit;
  }
  if (atclient_atkey_is_shared_with_initialized(atkey)) {
    free(atkey->shared_with);
    atkey->shared_with = NULL;
    atkey->_initialized_fields[ATCLIENT_ATKEY_SHARED_WITH_INDEX] &= ~ATCLIENT_ATKEY_SHARED_WITH_INITIALIZED;
  }
  atkey->shared_with = strdup(shared_with);
  if (atkey->shared_with == NULL) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "strdup failed\n");
    ret = 1;
    goto exit;
  }
  atkey->_initialized_fields[ATCLIENT_ATKEY_SHARED_WITH_INDEX] |= ATCLIENT_ATKEY_SHARED_WITH_INITIALIZED;
  ret = 0;
  goto exit;
exit: { return ret; }
}

void atclient_atkey_unset_key(atclient_atkey *atkey) {
  if (atclient_atkey_is_key_initialized(atkey)) {
    free(atkey->key);
    atkey->key = NULL;
    atkey->_initialized_fields[ATCLIENT_ATKEY_KEY_INDEX] &= ~ATCLIENT_ATKEY_KEY_INITIALIZED;
  }
}

void atclient_atkey_unset_namespace_str(atclient_atkey *atkey) {
  if (atclient_atkey_is_namespacestr_initialized(atkey)) {
    free(atkey->namespace_str);
    atkey->namespace_str = NULL;
    atkey->_initialized_fields[ATCLIENT_ATKEY_NAMESPACE_STR_INDEX] &= ~ATCLIENT_ATKEY_NAMESPACE_STR_INITIALIZED;
  }
}

void atclient_atkey_unset_shared_by(atclient_atkey *atkey) {
  if (atclient_atkey_is_shared_by_initialized(atkey)) {
    free(atkey->shared_by);
    atkey->shared_by = NULL;
    atkey->_initialized_fields[ATCLIENT_ATKEY_SHARED_BY_INDEX] &= ~ATCLIENT_ATKEY_SHARED_BY_INITIALIZED;
  }
}

void atclient_atkey_unset_shared_with(atclient_atkey *atkey) {
  if (atclient_atkey_is_shared_with_initialized(atkey)) {
    free(atkey->shared_with);
    atkey->shared_with = NULL;
    atkey->_initialized_fields[ATCLIENT_ATKEY_SHARED_WITH_INDEX] &= ~ATCLIENT_ATKEY_SHARED_WITH_INITIALIZED;
  }
}

atclient_atkey_type atclient_atkey_get_type(const atclient_atkey *atkey) {
  if (atclient_atkey_metadata_is_is_public_initialized(&(atkey->metadata)) && atkey->metadata.is_public &&
      !atclient_atkey_is_shared_with_initialized(atkey)) {
    return ATCLIENT_ATKEY_TYPE_PUBLIC_KEY;
  }
  if (atclient_atkey_is_shared_by_initialized(atkey) && atclient_atkey_is_shared_with_initialized(atkey)) {
    if (strcmp(atkey->shared_by, atkey->shared_with) == 0) { // special case
      return ATCLIENT_ATKEY_TYPE_SELF_KEY;
    }
    return ATCLIENT_ATKEY_TYPE_SHARED_KEY;
  }

  if (atclient_atkey_is_shared_by_initialized(atkey) && !atclient_atkey_is_shared_with_initialized(atkey)) {
    return ATCLIENT_ATKEY_TYPE_SELF_KEY;
  }
  return ATCLIENT_ATKEY_TYPE_UNKNOWN;
}

int atclient_atkey_create_public_key(atclient_atkey *atkey, const char *key, const char *shared_by,
                                    const char *namespace_str) {
  int ret = 1;

  if (atkey == NULL) {
    ret = 1;
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atkey is NULL. This is a required argument.\n");
    goto exit;
  }
  if (key == NULL) {
    ret = 1;
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "key is NULL. This is a required argument.\n");
    goto exit;
  }
  if (strlen(key) == 0) {
    ret = 1;
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "key is empty. This is a required argument.\n");
    goto exit;
  }
  if (shared_by == NULL) {
    ret = 1;
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "shared_by is NULL. This is a required argument.\n");
    goto exit;
  }
  if (strlen(shared_by) == 0) {
    ret = 1;
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "shared_by is empty. This is a required argument.\n");
    goto exit;
  }

  atclient_atkey_metadata_set_is_public(&(atkey->metadata), true);

  if ((ret = atclient_atkey_set_key(atkey, key)) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atclient_atkey_set_key failed\n");
    goto exit;
  }

  if ((ret = atclient_atkey_set_shared_by(atkey, shared_by)) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atclient_atkey_set_shared_by failed\n");
    goto exit;
  }

  if (namespace_str != NULL) {
    if ((ret = atclient_atkey_set_namespace_str(atkey, namespace_str)) != 0) {
      atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atclient_atkey_set_namespace_str failed\n");
      goto exit;
    }
  }

  ret = 0;
  goto exit;
exit: { return ret; }
}

int atclient_atkey_create_self_key(atclient_atkey *atkey, const char *key, const char *shared_by,
                                  const char *namespace_str) {
  int ret = 1;

  if (atkey == NULL) {
    ret = 1;
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atkey is NULL. This is a required argument.\n");
    goto exit;
  }

  if (key == NULL) {
    ret = 1;
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "key is NULL. This is a required argument.\n");
    goto exit;
  }

  if (strlen(key) <= 0) {
    ret = 1;
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "key is empty. This is a required argument.\n");
    goto exit;
  }

  if (shared_by == NULL) {
    ret = 1;
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "shared_by is NULL. This is a required argument.\n");
    goto exit;
  }

  if (strlen(shared_by) <= 0) {
    ret = 1;
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "shared_by is empty. This is a required argument.\n");
    goto exit;
  }

  if ((ret = atclient_atkey_set_key(atkey, key)) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atclient_atkey_set_key failed\n");
    goto exit;
  }

  if (namespace_str != NULL && strlen(namespace_str) > 0) {
    if ((ret = atclient_atkey_set_namespace_str(atkey, namespace_str)) != 0) {
      atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atclient_atkey_set_namespace_str failed\n");
      goto exit;
    }
  }

  if ((ret = atclient_atkey_set_shared_by(atkey, shared_by)) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atclient_atkey_set_shared_by failed\n");
    goto exit;
  }

  ret = 0;
  goto exit;
exit: { return ret; }
}

int atclient_atkey_create_shared_key(atclient_atkey *atkey, const char *key, const char *shared_by,
                                    const char *shared_with, const char *namespace_str) {
  int ret = 1;

  if (atkey == NULL) {
    ret = 1;
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atkey is NULL. This is a required argument.\n");
    goto exit;
  }

  if (key == NULL) {
    ret = 1;
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "key is NULL. This is a required argument.\n");
    goto exit;
  }

  if (strlen(key) <= 0) {
    ret = 1;
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "key is empty. This is a required argument.\n");
    goto exit;
  }

  if (shared_by == NULL) {
    ret = 1;
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "shared_by is NULL. This is a required argument.\n");
    goto exit;
  }

  if (strlen(shared_by) <= 0) {
    ret = 1;
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "shared_by is empty. This is a required argument.\n");
    goto exit;
  }

  if (shared_with == NULL) {
    ret = 1;
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "shared_with is NULL. This is a required argument.\n");
    goto exit;
  }

  if (strlen(shared_with) <= 0) {
    ret = 1;
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "shared_with is empty. This is a required argument.\n");
    goto exit;
  }

  if ((ret = atclient_atkey_set_shared_with(atkey, shared_with)) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atclient_atkey_set_shared_with failed\n");
    goto exit;
  }

  if ((ret = atclient_atkey_set_key(atkey, key)) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atclient_atkey_set_key failed\n");
    goto exit;
  }

  if (namespace_str != NULL && strlen(namespace_str) > 0) {
    if ((ret = atclient_atkey_set_namespace_str(atkey, namespace_str)) != 0) {
      atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atclient_atkey_set_namespace_str failed\n");
      goto exit;
    }
  }

  if ((ret = atclient_atkey_set_shared_by(atkey, shared_by)) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atclient_atkey_set_shared_by failed\n");
    goto exit;
  }

  ret = 0;
  goto exit;
exit: { return ret; }
}
