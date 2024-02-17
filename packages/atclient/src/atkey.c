#include "atclient/atkey.h"
#include "atclient/atsign.h"
#include "atclient/atstr.h"
#include "atclient/constants.h"
#include "atclient/metadata.h"
#include "atclient/stringutils.h"
#include "atlogger/atlogger.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>

#define TAG "atkey"

#define ATKEY_GENERAL_BUFFER_SIZE 4096 // sufficient memory for keyName, namespace, sharedWith, and sharedBy strings

void atclient_atkey_init(atclient_atkey *atkey) {
  memset(atkey, 0, sizeof(atclient_atkey));
  atclient_atstr_init(&(atkey->name), ATKEY_GENERAL_BUFFER_SIZE);
  atclient_atstr_init(&(atkey->namespacestr), ATKEY_GENERAL_BUFFER_SIZE);
  atclient_atstr_init(&(atkey->sharedby), ATKEY_GENERAL_BUFFER_SIZE);
  atclient_atstr_init(&(atkey->sharedwith), ATKEY_GENERAL_BUFFER_SIZE);

  atclient_atkey_metadata_init(&(atkey->metadata));
}

void atclient_atkey_free(atclient_atkey *atkey) {
  free(atkey->name.str);
  free(atkey->namespacestr.str);
  free(atkey->sharedwith.str);
  free(atkey->sharedby.str);
}

int atclient_atkey_from_string(atclient_atkey *atkey, const char *atkeystr, const unsigned long atkeylen) {
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
    atclient_atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "strdndup failed\n");
    goto exit;
  }
  char *token = strtok_r(copy, ":", &saveptr);
  unsigned long tokenlen = strlen(token);
  if (token == NULL) {
    atclient_atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "tokens[0] is NULL\n");
    ret = 1;
    goto exit;
  }
  // check if cached
  if (strncmp(token, "cached", strlen("cached")) == 0) {
    atkey->metadata.iscached = true;
    token = strtok_r(NULL, ":", &saveptr);
    if (token == NULL) {
      atclient_atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "tokens[1] is NULL\n");
      ret = 1;
      goto exit;
    }
  }

  if (atclient_stringutils_starts_with(token, tokenlen, "public", strlen("public")) == 1) {
    // it is a public key
    atkey->metadata.ispublic = true;
    atkey->atkeytype = ATCLIENT_ATKEY_TYPE_PUBLICKEY;
    // shift tokens array to the left
    token = strtok_r(NULL, ":", &saveptr);
    if (token == NULL) {
      atclient_atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "token is NULL. %s atkey is probably incomplete\n",
                            atkeystr);
      ret = 1;
      goto exit;
    }
  } else if (atclient_stringutils_starts_with(token, tokenlen, "@", strlen("@")) == 1) {
    // it is a shared key
    atkey->atkeytype = ATCLIENT_ATKEY_TYPE_SHAREDKEY;
    // set sharedwith
    ret = atclient_atstr_set_literal(&(atkey->sharedwith), token, tokenlen);
    if (ret != 0) {
      atclient_atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atclient_atstr_set_literal failed\n");
      goto exit;
    }
    token = strtok_r(NULL, ":", &saveptr);
    if (token == NULL) {
      atclient_atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "token is NULL. %s atkey is probably incomplete\n",
                            atkeystr);
      ret = 1;
      goto exit;
    }
  } else if (atclient_stringutils_starts_with(token, tokenlen, "_", strlen("_")) == 1) {
    // it is an internal key
    atkey->atkeytype = ATCLIENT_ATKEY_TYPE_SELFKEY;
    atkey->metadata.ishidden = 1;
  } else {
    // it is a self key
    atkey->atkeytype = ATCLIENT_ATKEY_TYPE_SELFKEY;
  }
  // set atkey->name
  token = strtok_r(token, "@", &saveptr);
  if (token == NULL) {
    atclient_atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "token is NULL. %s atkey is probably incomplete\n",
                          atkeystr);
    ret = 1;
    goto exit;
  }
  tokenlen = strlen(token);
  char nameandnamespacestr[ATSIGN_BUFFER_LENGTH];
  memset(nameandnamespacestr, 0, sizeof(char) * ATSIGN_BUFFER_LENGTH);
  memcpy(nameandnamespacestr, token, tokenlen);
  if (strchr(nameandnamespacestr, '.') != NULL) {
    // there is a namespace
    char *saveptr2;
    char *name = strtok_r(nameandnamespacestr, ".", &saveptr2);
    if (name == NULL) {
      atclient_atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "name is NULL. %s atkey is probably incomplete\n",
                            atkeystr);
      ret = 1;
      goto exit;
    }
    unsigned long namelen = strlen(name);
    ret = atclient_atstr_set_literal(&(atkey->name), name, namelen);
    if (ret != 0) {
      atclient_atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atclient_atstr_set_literal failed\n");
      goto exit;
    }
    char *namespacestr = strtok_r(NULL, ".", &saveptr2);
    if (namespacestr == NULL) {
      atclient_atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR,
                            "namespacestr is NULL. %s atkey is probably incomplete\n", atkeystr);
      ret = 1;
      goto exit;
    }
    unsigned long namespacestrlen = strlen(namespacestr);
    ret = atclient_atstr_set_literal(&(atkey->namespacestr), namespacestr, namespacestrlen);
    if (ret != 0) {
      atclient_atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atclient_atstr_set_literal failed\n");
      goto exit;
    }
  } else {
    // there is no namespace
    unsigned long namelen = strlen(nameandnamespacestr);
    ret = atclient_atstr_set_literal(&(atkey->name), nameandnamespacestr, namelen);
    if (ret != 0) {
      atclient_atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atclient_atstr_set_literal failed\n");
      goto exit;
    }
  }
  // set atkey->sharedby
  token = strtok_r(NULL, "", &saveptr);
  if (token == NULL) {
    atclient_atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "token is NULL. %s atkey is probably incomplete\n",
                          atkeystr);
    ret = 1;
    goto exit;
  }
  tokenlen = strlen(token);
  char sharedbystr[ATSIGN_BUFFER_LENGTH];
  memset(sharedbystr, 0, sizeof(char) * ATSIGN_BUFFER_LENGTH);
  unsigned long sharedbystrolen = 0;
  ret = atclient_atsign_with_at_symbol(sharedbystr, ATSIGN_BUFFER_LENGTH, &sharedbystrolen, token, tokenlen);
  if (ret != 0) {
    atclient_atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atclient_atsign_with_at_symbol failed\n");
    goto exit;
  }
  ret = atclient_atstr_set_literal(&(atkey->sharedby), sharedbystr, sharedbystrolen);
  if (ret != 0) {
    atclient_atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atclient_atstr_set_literal failed\n");
    goto exit;
  }
  ret = 0;
  goto exit;
exit: {
  free(copy);
  return ret;
}
}

int atclient_atkey_from_atstr(atclient_atkey *atkey, const atclient_atstr atstr) {
  return atclient_atkey_from_string(atkey, atstr.str, atstr.olen);
}

int atclient_atkey_to_string(const atclient_atkey atkey, char *atkeystr, const unsigned long atkeystrlen,
                             unsigned long *atkeystrolen) {
  int ret = 1;

  atclient_atstr string;
  atclient_atstr_init(&string, ATKEY_GENERAL_BUFFER_SIZE);

  if (atkey.metadata.iscached == true) {
    ret = atclient_atstr_append(&string, "cached:");
    if (ret != 0) {
      atclient_atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atclient_atstr_append_literal failed\n");
      goto exit;
    }
  }

  if (atkey.metadata.ispublic == true && atkey.atkeytype == ATCLIENT_ATKEY_TYPE_PUBLICKEY) {
    ret = atclient_atstr_append(&string, "public:");
    if (ret != 0) {
      atclient_atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atclient_atstr_append_literal failed\n");
      goto exit;
    }
  } else if (atkey.metadata.ispublic == true || atkey.atkeytype == ATCLIENT_ATKEY_TYPE_PUBLICKEY) {
    atclient_atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_WARN,
                          "either atkey's metadata ispublic is not set to 1 or atkey's atkeytype is not set to "
                          "ATCLIENT_ATKEY_TYPE_PUBLICKEY for atkey: %.*s\n",
                          (int)atkey.name.olen, atkey.name.str);
  } else if (atkey.atkeytype == ATCLIENT_ATKEY_TYPE_SHAREDKEY) {
    ret = atclient_atstr_append(&string, "%.*s:", (int)atkey.sharedwith.olen, atkey.sharedwith.str);
    if (ret != 0) {
      atclient_atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atclient_atstr_append_literal failed\n");
      goto exit;
    }
  } else if (atkey.atkeytype == NULL || atkey.atkeytype != ATCLIENT_ATKEY_TYPE_SELFKEY ||
             atkey.atkeytype == ATCLIENT_ATKEY_TYPE_UNKNOWN) {
    atclient_atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atkey's atkeytype is %d: %.*s\n", atkey.atkeytype,
                          (int)atkey.name.olen, atkey.name.str);
    ret = 1;
    goto exit;
  }

  if (atkey.name.str == NULL || atkey.name.olen == 0) {
    atclient_atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR,
                          "atkey's name is NULL or empty. atkey.name.str: \"%s\", atkey.name.olen: %d\n",
                          atkey.name.str, atkey.name.olen);
    ret = 1;
    goto exit;
  }
  ret = atclient_atstr_append(&string, atkey.name.str, atkey.name.olen);
  if (ret != 0) {
    atclient_atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atclient_atstr_append failed\n");
    goto exit;
  }

  if (atkey.namespacestr.olen > 0) {
    ret = atclient_atstr_append(&string, ".");
    if (ret != 0) {
      atclient_atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atclient_atstr_append_literal failed\n");
      goto exit;
    }
    ret = atclient_atstr_append(&string, atkey.namespacestr.str, atkey.namespacestr.olen);
    if (ret != 0) {
      atclient_atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atclient_atstr_append failed\n");
      goto exit;
    }
  }

  if (atkey.sharedby.str == NULL || atkey.sharedby.olen == 0) {
    atclient_atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR,
                          "atkey's sharedby is NULL or empty. atkey.sharedby.str: \"%s\", atkey.sharedby.olen: %d\n",
                          atkey.sharedby.str, atkey.sharedby.olen);
    ret = 1;
    goto exit;
  }
  ret = atclient_atstr_append(&string, "%.*s", (int)atkey.sharedby.olen, atkey.sharedby.str);
  if (ret != 0) {
    atclient_atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atclient_atstr_append failed\n");
    goto exit;
  }

  if (string.olen > atkeystrlen) {
    atclient_atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atkeystr is too small\n");
    ret = 1;
    goto exit;
  }

  memcpy(atkeystr, string.str, string.olen);
  *atkeystrolen = string.olen;

  ret = 0;
  goto exit;
exit: {
  atclient_atstr_free(&string);
  return ret;
}
}

int atclient_atkey_to_atstr(const atclient_atkey atkey, atclient_atstr *atstr) {
  int ret = 1;

  ret = atclient_atkey_to_string(atkey, atstr->str, atstr->olen, &(atstr->olen));
  if (ret != 0) {
    atclient_atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atclient_atkey_to_string failed\n");
    goto exit;
  }

  ret = 0;
  goto exit;
exit: { return ret; }
}

int atclient_atkey_create_publickey(atclient_atkey *atkey, const char *name, const size_t namelen, const char *sharedby,
                                    const size_t sharedbylen, const char *namespacestr, const size_t namespacestrlen) {
  int ret = 1;

  if(name == NULL || sharedby == NULL) {
    atclient_atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "name or sharedby is NULL. These are required arguments.\n");
    ret = 1;
    goto exit;
  }

  if(namelen == 0 || sharedbylen == 0) {
    atclient_atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "namelen or sharedbylen is 0. These are required arguments.\n");
    ret = 1;
    goto exit;
  }

  atkey->atkeytype = ATCLIENT_ATKEY_TYPE_PUBLICKEY;
  atkey->metadata.ispublic = true;

  ret = atclient_atstr_set_literal(&(atkey->name), name, namelen);
  if (ret != 0) {
    atclient_atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atclient_atstr_set_literal failed\n");
    goto exit;
  }

  ret = atclient_atstr_set_literal(&(atkey->sharedby), sharedby, sharedbylen);
  if (ret != 0) {
    atclient_atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atclient_atstr_set_literal failed\n");
    goto exit;
  }

  if (namespacestr != NULL) {
    ret = atclient_atstr_set_literal(&(atkey->namespacestr), namespacestr, namespacestrlen);
    if (ret != 0) {
      atclient_atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atclient_atstr_set_literal failed\n");
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

  if(name == NULL || sharedby == NULL) {
    atclient_atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "name or sharedby is NULL. These are required arguments.\n");
    ret = 1;
    goto exit;
  }

  if(namelen == 0 || sharedbylen == 0) {
    atclient_atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "namelen or sharedbylen is 0. These are required arguments.\n");
    ret = 1;
    goto exit;
  }

  atkey->atkeytype = ATCLIENT_ATKEY_TYPE_SELFKEY;

  ret = atclient_atstr_set_literal(&(atkey->name), name, namelen);
  if (ret != 0) {
    atclient_atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atclient_atstr_set_literal failed\n");
    goto exit;
  }

  if (namespacestr != NULL) {
    ret = atclient_atstr_set_literal(&(atkey->namespacestr), namespacestr, namespacestrlen);
    if (ret != 0) {
      atclient_atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atclient_atstr_set_literal failed\n");
      goto exit;
    }
  }

  ret = atclient_atstr_set_literal(&(atkey->sharedby), sharedby, sharedbylen);
  if (ret != 0) {
    atclient_atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atclient_atstr_set_literal failed\n");
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

  if(name == NULL || sharedby == NULL || sharedwith == NULL) {
    atclient_atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "name, sharedby, or sharedwith is NULL. These are required arguments.\n");
    ret = 1;
    goto exit;
  }

  if(namelen == 0 || sharedbylen == 0 || sharedwithlen == 0) {
    atclient_atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "namelen, sharedbylen, or sharedwithlen is 0. These are required arguments.\n");
    ret = 1;
    goto exit;
  }

  atkey->atkeytype = ATCLIENT_ATKEY_TYPE_SHAREDKEY;

  ret = atclient_atstr_set(&(atkey->sharedwith), sharedwith, sharedwithlen);
  if (ret != 0) {
    atclient_atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atclient_atstr_set failed\n");
    goto exit;
  }

  ret = atclient_atstr_set(&(atkey->name), name, namelen);
  if (ret != 0) {
    atclient_atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atclient_atstr_set failed\n");
    goto exit;
  }

  if(namespacestr != NULL) {
    ret = atclient_atstr_set(&(atkey->namespacestr), namespacestr, namespacestrlen);
    if (ret != 0) {
      atclient_atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atclient_atstr_set failed\n");
      goto exit;
    }
  }

  ret = atclient_atstr_set(&(atkey->sharedby), sharedby, sharedbylen);
  if (ret != 0) {
    atclient_atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atclient_atstr_set failed\n");
    goto exit;
  }

  ret = 0;
  goto exit;
exit: { return ret; }
}