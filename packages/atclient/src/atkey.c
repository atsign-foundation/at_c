#include "atclient/atkey.h"
#include "atclient/atsign.h"
#include "atclient/atstr.h"
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
  atkey->sharedby = NULL;
  atkey->sharedwith = NULL;
  atkey->namespacestr = NULL;
  memset(atkey->_initializedfields, 0, sizeof(atkey->_initializedfields));
  atclient_atkey_metadata_init(&(atkey->metadata));
}

void atclient_atkey_free(atclient_atkey *atkey) {
  atclient_atkey_metadata_free(&atkey->metadata);
  memset(atkey, 0, sizeof(atclient_atkey));
}

size_t atclient_atkey_strlen(const atclient_atkey *atkey) {
  if (atkey == NULL) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atkey is NULL\n");
    return -1;
  }
  if (!atclient_atkey_is_key_initialized(atkey) || !atclient_atkey_is_sharedby_initialized(atkey)) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atkey->key or atkey->sharedby is not initialized\n");
    return -1;
  }
  if (strlen(atkey->key) <= 0 || strlen(atkey->sharedby) <= 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atkey->key or atkey->sharedby is empty\n");
    return -1;
  }
  atclient_atkey_type type = atclient_atkey_get_type(atkey);
  if (type == ATCLIENT_ATKEY_TYPE_UNKNOWN) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atkey type is unknown\n");
    return -1;
  }
  size_t len = 0;
  if (atclient_atkey_metadata_is_iscached_initialized(&(atkey->metadata)) && atkey->metadata.iscached) {
    len += strlen("cached:");
  }
  if (atclient_atkey_metadata_is_ispublic_initialized(&(atkey->metadata)) && atkey->metadata.ispublic) {
    len += strlen("public:");
  }
  if (type == ATCLIENT_ATKEY_TYPE_SHAREDKEY && atclient_atkey_is_sharedwith_initialized(atkey)) {
    len += strlen(atkey->sharedwith) + strlen(":");
  }
  len += strlen(atkey->key);
  if (atclient_atkey_is_namespacestr_initialized(atkey) && strlen(atkey->namespacestr) > 0) {
    len += strlen(".") + strlen(atkey->namespacestr);
  }
  len += strlen(atkey->sharedby);
  return len;
}

int atclient_atkey_from_string(atclient_atkey *atkey, const char *atkeystr) {
  // 6 scenarios:
  // 1. PublicKey:            "public:name.wavi@smoothalligator"
  //      name == "name"
  //      sharedby = "smoothalligator"
  //      sharedwith = NULL
  //      namespace = "wavi"
  //      type = "public"
  //      cached = false
  // 2. PublicKey (cached):   "cached:public:name.wavi@smoothalligator"
  //      name == "name"
  //      sharedby = "smoothalligator"
  //      sharedwith = NULL
  //      namespace = "wavi"
  //      type = "public"
  //      cached = true
  // 3. SharedKey:            "@foo:name.wavi@bar"
  //      name == "name"
  //      sharedby = "bar"
  //      sharedwith = "foo"
  //      namespace = "wavi"
  //      cached = false
  // 4. SharedKey (cached):   "cached:@bar:name.wavi@foo"
  //      name == "name"
  //      sharedby = "foo"
  //      sharedwith = "bar"
  //      namespace = "wavi"
  //      cached = true
  // 5. SelfKey:              "name.wavi@smoothalligator"
  //      name == "name"
  //      sharedby = "smoothalligator"
  //      sharedwith = NULL
  //      namespace = "wavi"
  //      cached = false
  // more scenarios
  // 6. No Namespace, SelfKey:
  // "name@smoothalligator"
  //      name == "name"
  //      sharedby = "smoothalligator"
  //      sharedwith = NULL
  //      namespace = NULL
  //      cached = false
  int ret = 1;
  char *sharedby_withat = NULL;
  char *saveptr;
  const size_t compositesize = ATCLIENT_ATKEY_COMPOSITE_LEN + 1;
  char composite[compositesize]; // holds {key}.{namespace}
  memset(composite, 0, sizeof(char) * compositesize);
  char *copy = strdup(atkeystr);
  if (copy == NULL) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "strdndup failed\n");
    goto exit;
  }
  char *token = strtok_r(copy, ":", &saveptr);
  if (token == NULL) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "tokens[0] is NULL\n");
    ret = 1;
    goto exit;
  }
  size_t tokenlen = strlen(token);
  // check if cached
  if (strncmp(token, "cached", strlen("cached")) == 0) {
    atclient_atkey_metadata_set_iscached(&(atkey->metadata), true);
    token = strtok_r(NULL, ":", &saveptr);
    if (token == NULL) {
      atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "tokens[1] is NULL\n");
      ret = 1;
      goto exit;
    }
  }

  if (atclient_stringutils_starts_with(token, "public")) {
    // it is a public key
    atclient_atkey_metadata_set_ispublic(&(atkey->metadata), true);
    // shift tokens array to the left
    token = strtok_r(NULL, ":", &saveptr);
    if (token == NULL) {
      atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "token is NULL. %s atkey is probably incomplete\n", atkeystr);
      ret = 1;
      goto exit;
    }
  } else if (atclient_stringutils_starts_with(token, "@")) {
    // it is a shared key
    // set sharedwith
    if ((ret = atclient_atkey_set_sharedwith(atkey, token)) != 0) {
      atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atclient_atkey_set_sharedwith failed\n");
      goto exit;
    }
    token = strtok_r(NULL, ":", &saveptr);
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
  token = strtok_r(token, "@", &saveptr);
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

    char *namespacestr = strtok_r(NULL, "", &saveptr2);
    if (namespacestr == NULL) {
      ret = 1;
      atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "namespacestr is NULL. %s atkey is probably incomplete\n",
                   atkeystr);
      goto exit;
    }
    if ((ret = atclient_atkey_set_namespacestr(atkey, namespacestr)) != 0) {
      atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atclient_atkey_set_namespacestr failed\n");
      goto exit;
    }
  } else { // there is no namespace
    if ((ret = atclient_atkey_set_key(atkey, composite)) != 0) {
      atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atclient_atkey_set_key failed\n");
      goto exit;
    }
  }

  // set atkey->sharedby
  token = strtok_r(NULL, "", &saveptr);
  if (token == NULL) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "token is NULL. %s atkey is probably incomplete\n", atkeystr);
    ret = 1;
    goto exit;
  }
  tokenlen = strlen(token);

  if ((ret = atclient_stringutils_atsign_with_at(token, &sharedby_withat)) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atclient_stringutils_atsign_with_at failed\n");
    goto exit;
  }

  if ((ret = atclient_atkey_set_sharedby(atkey, sharedby_withat)) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atclient_atkey_set_sharedby failed\n");
    goto exit;
  }

  ret = 0;
  goto exit;
exit: {
  free(copy);
  free(sharedby_withat);
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

  atclient_atkey_type atkeytype = atclient_atkey_get_type(atkey);

  if (atkeytype == ATCLIENT_ATKEY_TYPE_UNKNOWN) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atkeytype is unknown\n");
    return ret;
  }

  if (!atclient_atkey_is_sharedby_initialized(atkey) || strlen(atkey->sharedby) <= 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR,
                 "atkey->sharedby is not initialized or strlen(atkey->sharedby) <= 0. AtKey is incomplete.\n");
    return ret;
  }

  if (!atclient_atkey_is_key_initialized(atkey) || strlen(atkey->key) <= 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR,
                 "atkey->key is not initialized or strlen(atkey->key) <= 0. AtKey is incomplete.\n");
    return ret;
  }

  size_t index_pos = 0;
  const size_t atkeystrsize = atclient_atkey_strlen(atkey) + 1;
  if ((*atkeystr = (char *)malloc(sizeof(char) * atkeystrsize)) == NULL) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "malloc failed\n");
    goto error_exit;
  }
  memset(*atkeystr, 0, sizeof(char) * atkeystrsize);

  if (atclient_atkey_metadata_is_iscached_initialized(&(atkey->metadata)) && atkey->metadata.iscached) {
    snprintf(*atkeystr + index_pos, atkeystrsize - index_pos, "cached:");
    index_pos += strlen("cached:");
  }

  if (atkeytype == ATCLIENT_ATKEY_TYPE_PUBLICKEY) {
    if (!atclient_atkey_metadata_is_ispublic_initialized(&(atkey->metadata)) || !atkey->metadata.ispublic) {
      atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_WARN,
                   "atkey's metadata ispublic is either not initialized or false, even though it was deemed a "
                   "ATCLIENT_ATKEY_TYPE_PUBLICKEY by atclient_atkey_get_type\n");
    }
    snprintf(*atkeystr + index_pos, atkeystrsize - index_pos, "public:");
    index_pos += strlen("public:");
  } else if (atkeytype == ATCLIENT_ATKEY_TYPE_SHAREDKEY) {
    if (atclient_atkey_is_sharedwith_initialized(atkey)) {
      atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_WARN,
                   "atkey's sharedwith is initialized, even though it was deemed a ATCLIENT_ATKEY_TYPE_SHAREDKEY by "
                   "atclient_atkey_get_type\n");
    }
    snprintf(*atkeystr + index_pos, atkeystrsize - index_pos, "%s:", atkey->sharedwith);
    index_pos += strlen(atkey->sharedwith) + strlen(":");
  }

  snprintf(*atkeystr + index_pos, atkeystrsize - index_pos, "%s", atkey->key);
  index_pos += strlen(atkey->key);

  if (atclient_atkey_is_namespacestr_initialized(atkey) && strlen(atkey->namespacestr) > 0) {
    snprintf(*atkeystr + index_pos, atkeystrsize - index_pos, ".%s", atkey->namespacestr);
    index_pos += strlen(".") + strlen(atkey->namespacestr);
  }

  snprintf(*atkeystr + index_pos, atkeystrsize - index_pos, "%s", atkey->sharedby);
  index_pos += strlen(atkey->sharedby);

  if (index_pos != atkeystrsize - 1) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_WARN,
                 "index_pos != atkeystrsize - 1 (%d != %d - 1). The predicted `atkeystrsize` variable was not "
                 "evaluated correctly.\n",
                 index_pos, atkeystrsize);
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
  return (atkey->_initializedfields[ATKEY_KEY_INDEX] & ATKEY_KEY_INITIALIZED);
}

bool atclient_atkey_is_namespacestr_initialized(const atclient_atkey *atkey) {
  return (atkey->_initializedfields[ATKEY_NAMESPACESTR_INDEX] & ATKEY_NAMESPACESTR_INITIALIZED);
}

bool atclient_atkey_is_sharedby_initialized(const atclient_atkey *atkey) {
  return (atkey->_initializedfields[ATKEY_SHAREDBY_INDEX] & ATKEY_SHAREDBY_INITIALIZED);
}

bool atclient_atkey_is_sharedwith_initialized(const atclient_atkey *atkey) {
  return (atkey->_initializedfields[ATKEY_SHAREDWITH_INDEX] & ATKEY_SHAREDWITH_INITIALIZED);
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
    atkey->_initializedfields[ATKEY_KEY_INDEX] &= ~ATKEY_KEY_INITIALIZED;
  }
  atkey->key = strdup(key);
  if (atkey->key == NULL) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "strdup failed\n");
    ret = 1;
    goto exit;
  }
  atkey->_initializedfields[ATKEY_KEY_INDEX] |= ATKEY_KEY_INITIALIZED;
  ret = 0;
  goto exit;
exit: { return ret; }
}

int atclient_atkey_set_namespacestr(atclient_atkey *atkey, const char *namespacestr) {
  int ret = 1;
  if (atkey == NULL) {
    ret = 1;
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atkey is NULL. This is a required argument.\n");
    goto exit;
  }
  if (namespacestr == NULL) {
    ret = 1;
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "namespacestr is NULL. This is a required argument.\n");
    goto exit;
  }
  if (atclient_atkey_is_namespacestr_initialized(atkey)) {
    free(atkey->namespacestr);
    atkey->namespacestr = NULL;
    atkey->_initializedfields[ATKEY_NAMESPACESTR_INDEX] &= ~ATKEY_NAMESPACESTR_INITIALIZED;
  }
  atkey->namespacestr = strdup(namespacestr);
  if (atkey->namespacestr == NULL) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "strdup failed\n");
    ret = 1;
    goto exit;
  }
  atkey->_initializedfields[ATKEY_NAMESPACESTR_INDEX] |= ATKEY_NAMESPACESTR_INITIALIZED;
  ret = 0;
  goto exit;
exit: { return ret; }
}

int atclient_atkey_set_sharedby(atclient_atkey *atkey, const char *sharedby) {
  int ret = 1;
  if (atkey == NULL) {
    ret = 1;
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atkey is NULL. This is a required argument.\n");
    goto exit;
  }
  if (sharedby == NULL) {
    ret = 1;
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "sharedby is NULL. This is a required argument.\n");
    goto exit;
  }
  if (atclient_atkey_is_sharedby_initialized(atkey)) {
    free(atkey->sharedby);
    atkey->sharedby = NULL;
    atkey->_initializedfields[ATKEY_SHAREDBY_INDEX] &= ~ATKEY_SHAREDBY_INITIALIZED;
  }
  atkey->sharedby = strdup(sharedby);
  if (atkey->sharedby == NULL) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "strdup failed\n");
    ret = 1;
    goto exit;
  }
  atkey->_initializedfields[ATKEY_SHAREDBY_INDEX] |= ATKEY_SHAREDBY_INITIALIZED;
  ret = 0;
  goto exit;
exit: { return ret; }
}

int atclient_atkey_set_sharedwith(atclient_atkey *atkey, const char *sharedwith) {
  int ret = 1;
  if (atkey == NULL) {
    ret = 1;
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atkey is NULL. This is a required argument.\n");
    goto exit;
  }
  if (sharedwith == NULL) {
    ret = 1;
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "sharedwith is NULL. This is a required argument.\n");
    goto exit;
  }
  if (atclient_atkey_is_sharedwith_initialized(atkey)) {
    free(atkey->sharedwith);
    atkey->sharedwith = NULL;
    atkey->_initializedfields[ATKEY_SHAREDWITH_INDEX] &= ~ATKEY_SHAREDWITH_INITIALIZED;
  }
  atkey->sharedwith = strdup(sharedwith);
  if (atkey->sharedwith == NULL) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "strdup failed\n");
    ret = 1;
    goto exit;
  }
  atkey->_initializedfields[ATKEY_SHAREDWITH_INDEX] |= ATKEY_SHAREDWITH_INITIALIZED;
  ret = 0;
  goto exit;
exit: { return ret; }
}

void atclient_atkey_unset_key(atclient_atkey *atkey) {
  if (atclient_atkey_is_key_initialized(atkey)) {
    free(atkey->key);
    atkey->key = NULL;
    atkey->_initializedfields[ATKEY_KEY_INDEX] &= ~ATKEY_KEY_INITIALIZED;
  }
}

void atclient_atkey_unset_namespacestr(atclient_atkey *atkey) {
  if (atclient_atkey_is_namespacestr_initialized(atkey)) {
    free(atkey->namespacestr);
    atkey->namespacestr = NULL;
    atkey->_initializedfields[ATKEY_NAMESPACESTR_INDEX] &= ~ATKEY_NAMESPACESTR_INITIALIZED;
  }
}

void atclient_atkey_unset_sharedby(atclient_atkey *atkey) {
  if (atclient_atkey_is_sharedby_initialized(atkey)) {
    free(atkey->sharedby);
    atkey->sharedby = NULL;
    atkey->_initializedfields[ATKEY_SHAREDBY_INDEX] &= ~ATKEY_SHAREDBY_INITIALIZED;
  }
}

void atclient_atkey_unset_sharedwith(atclient_atkey *atkey) {
  if (atclient_atkey_is_sharedwith_initialized(atkey)) {
    free(atkey->sharedwith);
    atkey->sharedwith = NULL;
    atkey->_initializedfields[ATKEY_SHAREDWITH_INDEX] &= ~ATKEY_SHAREDWITH_INITIALIZED;
  }
}

atclient_atkey_type atclient_atkey_get_type(const atclient_atkey *atkey) {
  if (atclient_atkey_metadata_is_ispublic_initialized(&(atkey->metadata)) && atkey->metadata.ispublic &&
      !atclient_atkey_is_sharedwith_initialized(atkey)) {
    return ATCLIENT_ATKEY_TYPE_PUBLICKEY;
  }
  if (atclient_atkey_is_sharedby_initialized(atkey) && atclient_atkey_is_sharedwith_initialized(atkey)) {
    if (strcmp(atkey->sharedby, atkey->sharedwith) == 0) { // special case
      return ATCLIENT_ATKEY_TYPE_SELFKEY;
    }
    return ATCLIENT_ATKEY_TYPE_SHAREDKEY;
  }

  if (atclient_atkey_is_sharedby_initialized(atkey) && !atclient_atkey_is_sharedwith_initialized(atkey)) {
    return ATCLIENT_ATKEY_TYPE_SELFKEY;
  }
  return ATCLIENT_ATKEY_TYPE_UNKNOWN;
}

int atclient_atkey_create_publickey(atclient_atkey *atkey, const char *key, const char *sharedby,
                                    const char *namespacestr) {
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
  if (sharedby == NULL) {
    ret = 1;
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "sharedby is NULL. This is a required argument.\n");
    goto exit;
  }
  if (strlen(sharedby) == 0) {
    ret = 1;
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "sharedby is empty. This is a required argument.\n");
    goto exit;
  }

  atclient_atkey_metadata_set_ispublic(&(atkey->metadata), true);

  if ((ret = atclient_atkey_set_key(atkey, key)) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atclient_atkey_set_key failed\n");
    goto exit;
  }

  if ((ret = atclient_atkey_set_sharedby(atkey, sharedby)) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atclient_atkey_set_sharedby failed\n");
    goto exit;
  }

  if (namespacestr != NULL) {
    if ((ret = atclient_atkey_set_namespacestr(atkey, namespacestr)) != 0) {
      atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atclient_atkey_set_namespacestr failed\n");
      goto exit;
    }
  }

  ret = 0;
  goto exit;
exit: { return ret; }
}

int atclient_atkey_create_selfkey(atclient_atkey *atkey, const char *key, const char *sharedby,
                                  const char *namespacestr) {
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

  if (sharedby == NULL) {
    ret = 1;
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "sharedby is NULL. This is a required argument.\n");
    goto exit;
  }

  if (strlen(sharedby) <= 0) {
    ret = 1;
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "sharedby is empty. This is a required argument.\n");
    goto exit;
  }

  if ((ret = atclient_atkey_set_key(atkey, key)) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atclient_atkey_set_key failed\n");
    goto exit;
  }

  if (namespacestr != NULL && strlen(namespacestr) > 0) {
    if ((ret = atclient_atkey_set_namespacestr(atkey, namespacestr)) != 0) {
      atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atclient_atkey_set_namespacestr failed\n");
      goto exit;
    }
  }

  if ((ret = atclient_atkey_set_sharedby(atkey, sharedby)) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atclient_atkey_set_sharedby failed\n");
    goto exit;
  }

  ret = 0;
  goto exit;
exit: { return ret; }
}

int atclient_atkey_create_sharedkey(atclient_atkey *atkey, const char *key, const char *sharedby,
                                    const char *sharedwith, const char *namespacestr) {
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

  if (sharedby == NULL) {
    ret = 1;
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "sharedby is NULL. This is a required argument.\n");
    goto exit;
  }

  if (strlen(sharedby) <= 0) {
    ret = 1;
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "sharedby is empty. This is a required argument.\n");
    goto exit;
  }

  if (sharedwith == NULL) {
    ret = 1;
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "sharedwith is NULL. This is a required argument.\n");
    goto exit;
  }

  if (strlen(sharedwith) <= 0) {
    ret = 1;
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "sharedwith is empty. This is a required argument.\n");
    goto exit;
  }

  if ((ret = atclient_atkey_set_sharedwith(atkey, sharedwith)) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atclient_atkey_set_sharedwith failed\n");
    goto exit;
  }

  if ((ret = atclient_atkey_set_key(atkey, key)) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atclient_atkey_set_key failed\n");
    goto exit;
  }

  if (namespacestr != NULL && strlen(namespacestr) > 0) {
    if ((ret = atclient_atkey_set_namespacestr(atkey, namespacestr)) != 0) {
      atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atclient_atkey_set_namespacestr failed\n");
      goto exit;
    }
  }

  if ((ret = atclient_atkey_set_sharedby(atkey, sharedby)) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atclient_atkey_set_sharedby failed\n");
    goto exit;
  }

  ret = 0;
  goto exit;
exit: { return ret; }
}
