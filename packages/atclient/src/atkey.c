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
  atclient_atstr_init(&(atkey->name), ATCLIENT_ATKEY_KEY_LEN + 1);
  atclient_atstr_init(&(atkey->namespacestr), ATCLIENT_ATKEY_NAMESPACE_LEN + 1);
  atclient_atstr_init(&(atkey->sharedby), ATCLIENT_ATKEY_FULL_LEN);
  atclient_atstr_init(&(atkey->sharedwith), ATCLIENT_ATKEY_FULL_LEN);

  atclient_atkey_metadata_init(&(atkey->metadata));
}

void atclient_atkey_free(atclient_atkey *atkey) {
  free(atkey->name.str);
  free(atkey->namespacestr.str);
  free(atkey->sharedwith.str);
  free(atkey->sharedby.str);

  atclient_atkey_metadata_free(&atkey->metadata);
}

int atclient_atkey_from_string(atclient_atkey *atkey, const char *atkeystr, const size_t atkeylen) {
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
  char *saveptr;
  char *copy = strndup(atkeystr, atkeylen);
  if (copy == NULL) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "strdndup failed\n");
    goto exit;
  }
  char *token = strtok_r(copy, ":", &saveptr);
  size_t tokenlen = strlen(token);
  if (token == NULL) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "tokens[0] is NULL\n");
    ret = 1;
    goto exit;
  }
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

  if (atclient_stringutils_starts_with(token, tokenlen, "public", strlen("public")) == 1) {
    // it is a public key
    atclient_atkey_metadata_set_ispublic(&(atkey->metadata), true);
    atkey->atkeytype = ATCLIENT_ATKEY_TYPE_PUBLICKEY;
    // shift tokens array to the left
    token = strtok_r(NULL, ":", &saveptr);
    if (token == NULL) {
      atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "token is NULL. %s atkey is probably incomplete\n", atkeystr);
      ret = 1;
      goto exit;
    }
  } else if (atclient_stringutils_starts_with(token, tokenlen, "@", strlen("@")) == 1) {
    // it is a shared key
    atkey->atkeytype = ATCLIENT_ATKEY_TYPE_SHAREDKEY;
    // set sharedwith
    ret = atclient_atstr_set_literal(&(atkey->sharedwith), token, tokenlen);
    if (ret != 0) {
      atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atclient_atstr_set_literal failed\n");
      goto exit;
    }
    token = strtok_r(NULL, ":", &saveptr);
    if (token == NULL) {
      atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "token is NULL. %s atkey is probably incomplete\n", atkeystr);
      ret = 1;
      goto exit;
    }
  } else if (atclient_stringutils_starts_with(token, tokenlen, "_", strlen("_")) == 1) {
    // it is an internal key
    atkey->atkeytype = ATCLIENT_ATKEY_TYPE_SELFKEY;
    atclient_atkey_metadata_set_ishidden(&(atkey->metadata), true);
  } else {
    // it is a self key
    atkey->atkeytype = ATCLIENT_ATKEY_TYPE_SELFKEY;
  }
  // set atkey->name
  token = strtok_r(token, "@", &saveptr);
  if (token == NULL) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "token is NULL. %s atkey is probably incomplete\n", atkeystr);
    ret = 1;
    goto exit;
  }
  tokenlen = strlen(token);
  char nameandnamespacestr[ATCLIENT_ATKEY_COMPOSITE_LEN + 1];
  memset(nameandnamespacestr, 0, sizeof(char) * ATCLIENT_ATKEY_COMPOSITE_LEN + 1);
  memcpy(nameandnamespacestr, token, tokenlen);
  char *check = strchr(nameandnamespacestr, '.');
  if (check != NULL && *(check + 1) != '\0') {
    // there is a namespace
    char *saveptr2;
    char *name = strtok_r(nameandnamespacestr, ".", &saveptr2);
    if (name == NULL) {
      atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "name is NULL. %s atkey is probably incomplete\n", atkeystr);
      ret = 1;
      goto exit;
    }
    size_t namelen = strlen(name);
    ret = atclient_atstr_set_literal(&(atkey->name), name, namelen);
    if (ret != 0) {
      atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atclient_atstr_set_literal failed\n");
      goto exit;
    }
    char *namespacestr = strtok_r(NULL, "", &saveptr2);
    if (namespacestr == NULL) {
      atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "namespacestr is NULL. %s atkey is probably incomplete\n",
                   atkeystr);
      ret = 1;
      goto exit;
    }
    size_t namespacestrlen = strlen(namespacestr);
    ret = atclient_atstr_set_literal(&(atkey->namespacestr), namespacestr, namespacestrlen);
    if (ret != 0) {
      atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atclient_atstr_set_literal failed\n");
      goto exit;
    }
  } else {
    // there is no namespace
    size_t namelen = strlen(nameandnamespacestr);
    ret = atclient_atstr_set_literal(&(atkey->name), nameandnamespacestr, namelen);
    if (ret != 0) {
      atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atclient_atstr_set_literal failed\n");
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
  char sharedbystr[ATCLIENT_ATKEY_FULL_LEN + 1];
  memset(sharedbystr, 0, sizeof(char) * ATCLIENT_ATKEY_FULL_LEN + 1);
  size_t sharedbystrlen = 0;
  ret = atclient_atsign_with_at_symbol(sharedbystr, ATCLIENT_ATSIGN_FULL_LEN, &sharedbystrlen, token, tokenlen);
  if (ret != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atclient_atsign_with_at_symbol failed\n");
    goto exit;
  }
  ret = atclient_atstr_set_literal(&(atkey->sharedby), sharedbystr, sharedbystrlen);
  if (ret != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atclient_atstr_set_literal failed\n");
    goto exit;
  }
  ret = 0;
  goto exit;
exit: {
  free(copy);
  return ret;
}
}

size_t atclient_atkey_strlen(const atclient_atkey *atkey) {
  size_t len = 0;
  if (atclient_atkey_metadata_is_iscached_initialized(&(atkey->metadata)) && atkey->metadata.iscached) {
    len += strlen("cached:");
  }
  if (atclient_atkey_metadata_is_ispublic_initialized(&(atkey->metadata)) && atkey->metadata.ispublic) {
    len += strlen("public:");
  }
  if (atkey->atkeytype == ATCLIENT_ATKEY_TYPE_SHAREDKEY) {
    len += atkey->sharedwith.len + strlen(":");
  }
  len += atkey->name.len;
  if (atkey->namespacestr.len > 0) {
    len += strlen(".") + atkey->namespacestr.len;
  }
  len += atkey->sharedby.len;
  return len;
}

int atclient_atkey_to_string(const atclient_atkey *atkey, char **atkeystr) {
  int ret = 1;

  size_t index_pos = 0;

  const size_t atkeystrsize = atclient_atkey_strlen(atkey) + 1;
  *atkeystr = (char *)malloc(sizeof(char) * atkeystrsize);
  if (*atkeystr == NULL) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "malloc failed\n");
    goto error_exit;
  }
  memset(*atkeystr, 0, sizeof(char) * atkeystrsize);

  if (atclient_atkey_metadata_is_iscached_initialized(&(atkey->metadata)) && atkey->metadata.iscached) {
    snprintf(*atkeystr + index_pos, atkeystrsize - index_pos, "cached:");
    index_pos += strlen("cached:");
  }

  if (atclient_atkey_metadata_is_ispublic_initialized(&(atkey->metadata)) && atkey->metadata.ispublic &&
      atkey->atkeytype == ATCLIENT_ATKEY_TYPE_PUBLICKEY) {
    snprintf(*atkeystr + index_pos, atkeystrsize - index_pos, "public:");
    index_pos += strlen("public:");
  } else if (atkey->metadata.ispublic || atkey->atkeytype == ATCLIENT_ATKEY_TYPE_PUBLICKEY) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_WARN,
                 "either atkey's metadata ispublic is not set to 1 or atkey's atkeytype is not set to "
                 "ATCLIENT_ATKEY_TYPE_PUBLICKEY for atkey: %.*s\n",
                 (int)atkey->name.len, atkey->name.str);
    snprintf(*atkeystr + index_pos, atkeystrsize - index_pos, "public:");
    index_pos += strlen("public:");
  } else if (atkey->atkeytype == ATCLIENT_ATKEY_TYPE_SHAREDKEY) {
    snprintf(*atkeystr + index_pos, atkeystrsize - index_pos, "%.*s:", (int)atkey->sharedwith.len,
             atkey->sharedwith.str);
    index_pos += (atkey->sharedwith.len) + strlen(":");
  } else if (atkey->atkeytype == ATCLIENT_ATKEY_TYPE_UNKNOWN) {
    ret = 1;
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atkey's atkeytype is %d: %.*s\n", atkey->atkeytype,
                 (int)atkey->name.len, atkey->name.str);
    goto error_exit;
  }

  if (atkey->name.str == NULL || atkey->name.len == 0) {
    ret = 1;
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR,
                 "atkey's name is NULL or empty. atkey.name.str: \"%s\", atkey.name.len: %d\n", atkey->name.str,
                 atkey->name.len);
    goto error_exit;
  }

  snprintf(*atkeystr + index_pos, atkeystrsize - index_pos, "%.*s", (int)atkey->name.len, atkey->name.str);
  index_pos += atkey->name.len;

  if (atkey->namespacestr.len > 0) {
    snprintf(*atkeystr + index_pos, atkeystrsize - index_pos, ".%.*s", (int)atkey->namespacestr.len,
             atkey->namespacestr.str);
    index_pos += strlen(".") + atkey->namespacestr.len;
  }

  if (atkey->sharedby.str == NULL || atkey->sharedby.len == 0) {
    ret = 1;
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR,
                 "atkey's sharedby is NULL or empty. atkey.sharedby.str: \"%s\", atkey.sharedby.len: %d\n",
                 atkey->sharedby.str, atkey->sharedby.len);
    goto error_exit;
  }

  snprintf(*atkeystr + index_pos, atkeystrsize - index_pos, "%.*s", (int)atkey->sharedby.len, atkey->sharedby.str);
  index_pos += (int)atkey->sharedby.len;

  if (strlen(*atkeystr) > atkeystrsize) {
    ret = 1;
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR,
                 "atkeystr is too small. Conditiion strlen(atkey)str > atkeystrsize: %d > %d, is true\n",
                 strlen(*atkeystr), atkeystrsize);
    goto error_exit;
  }

  ret = 0;
  goto exit;
error_exit: {
  free(*atkeystr);
  goto exit;
}
exit: { return ret; }
}

int atclient_atkey_create_publickey(atclient_atkey *atkey, const char *name, const size_t namelen, const char *sharedby,
                                    const size_t sharedbylen, const char *namespacestr, const size_t namespacestrlen) {
  int ret = 1;

  if (name == NULL || sharedby == NULL) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "name or sharedby is NULL. These are required arguments.\n");
    ret = 1;
    goto exit;
  }

  if (namelen == 0 || sharedbylen == 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "namelen or sharedbylen is 0. These are required arguments.\n");
    ret = 1;
    goto exit;
  }

  atkey->atkeytype = ATCLIENT_ATKEY_TYPE_PUBLICKEY;
  atclient_atkey_metadata_set_ispublic(&(atkey->metadata), true);

  ret = atclient_atstr_set_literal(&(atkey->name), name, namelen);
  if (ret != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atclient_atstr_set_literal failed\n");
    goto exit;
  }

  ret = atclient_atstr_set_literal(&(atkey->sharedby), sharedby, sharedbylen);
  if (ret != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atclient_atstr_set_literal failed\n");
    goto exit;
  }

  if (namespacestr != NULL) {
    ret = atclient_atstr_set_literal(&(atkey->namespacestr), namespacestr, namespacestrlen);
    if (ret != 0) {
      atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atclient_atstr_set_literal failed\n");
      goto exit;
    }
  }

  ret = 0;
  goto exit;
exit: { return ret; }
}

int atclient_atkey_create_selfkey(atclient_atkey *atkey, const char *name, const size_t namelen, const char *sharedby,
                                  const size_t sharedbylen, const char *namespacestr, const size_t namespacestrlen) {
  int ret = 1;

  if (name == NULL || sharedby == NULL) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "name or sharedby is NULL. These are required arguments.\n");
    ret = 1;
    goto exit;
  }

  if (namelen == 0 || sharedbylen == 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "namelen or sharedbylen is 0. These are required arguments.\n");
    ret = 1;
    goto exit;
  }

  atkey->atkeytype = ATCLIENT_ATKEY_TYPE_SELFKEY;

  ret = atclient_atstr_set_literal(&(atkey->name), "%.*s", (int)namelen, name);
  if (ret != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atclient_atstr_set_literal failed\n");
    goto exit;
  }

  if (namespacestr != NULL) {
    if (namespacestrlen == 0) {
      atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "namespacestrlen is 0. This is a required argument.\n");
      ret = 1;
      goto exit;
    }
    ret = atclient_atstr_set_literal(&(atkey->namespacestr), "%.*s", (int)namespacestrlen, namespacestr);
    if (ret != 0) {
      atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atclient_atstr_set_literal failed\n");
      goto exit;
    }
  }

  ret = atclient_atstr_set_literal(&(atkey->sharedby), "%.*s", (int)sharedbylen, sharedby);
  if (ret != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atclient_atstr_set_literal failed\n");
    goto exit;
  }

  ret = 0;
  goto exit;
exit: { return ret; }
}

int atclient_atkey_create_sharedkey(atclient_atkey *atkey, const char *name, const size_t namelen, const char *sharedby,
                                    const size_t sharedbylen, const char *sharedwith, const size_t sharedwithlen,
                                    const char *namespacestr, const size_t namespacestrlen) {
  int ret = 1;

  if (name == NULL || sharedby == NULL || sharedwith == NULL) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR,
                 "name, sharedby, or sharedwith is NULL. These are required arguments.\n");
    ret = 1;
    goto exit;
  }

  if (namelen == 0 || sharedbylen == 0 || sharedwithlen == 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR,
                 "namelen, sharedbylen, or sharedwithlen is 0. These are required arguments.\n");
    ret = 1;
    goto exit;
  }

  atkey->atkeytype = ATCLIENT_ATKEY_TYPE_SHAREDKEY;

  ret = atclient_atstr_set(&(atkey->sharedwith), sharedwith, sharedwithlen);
  if (ret != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atclient_atstr_set failed\n");
    goto exit;
  }

  ret = atclient_atstr_set(&(atkey->name), name, namelen);
  if (ret != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atclient_atstr_set failed\n");
    goto exit;
  }

  if (namespacestr != NULL) {
    ret = atclient_atstr_set(&(atkey->namespacestr), namespacestr, namespacestrlen);
    if (ret != 0) {
      atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atclient_atstr_set failed\n");
      goto exit;
    }
  }

  ret = atclient_atstr_set(&(atkey->sharedby), sharedby, sharedbylen);
  if (ret != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atclient_atstr_set failed\n");
    goto exit;
  }

  ret = 0;
  goto exit;
exit: { return ret; }
}
