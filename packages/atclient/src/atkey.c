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
  // 5. PrivateHiddenKey:     "_latestnotificationid.wavi@smoothalligator"
  //      name == "_latestnotificationid"
  //      sharedby = "smoothalligator"
  //      namespace = "wavi"
  //      cached = false
  // 6. SelfKey:              "name.wavi@smoothalligator"
  //      name == "name"
  //      sharedby = "smoothalligator"
  //      sharedwith = NULL
  //      namespace = "wavi"
  //      cached = false
  // more scenarios
  // 7. No Namespace, SelfKey:
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
    atkey->metadata.iscached = 1;
    token = strtok_r(NULL, ":", &saveptr);
    if (token == NULL) {
      atclient_atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "tokens[1] is NULL\n");
      ret = 1;
      goto exit;
    }
  }

  if (atclient_stringutils_starts_with(token, tokenlen, "public", strlen("public")) == 1) {
    // it is a public key
    atkey->metadata.ispublic = 1;
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
    // it is a private hidden key
    atkey->atkeytype = ATCLIENT_ATKEY_TYPE_PRIVATEHIDDENKEY;
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

int atclient_atkey_to_string(const atclient_atkey atkey, char *atkeystr, unsigned long *atkeystrlen,
                             unsigned long *atkeystrolen) {
  return 1; // TODO: implement
}

int atclient_atkey_create_publickey(atclient_atkey *atkey, const char *name, const char *sharedby,
                                    const char *namespacestr) {
  return 1; // TODO: implement
}

int atclient_atkey_create_selfkey(atclient_atkey *atkey, const char *name, const char *sharedby,
                                  const char *namespacestr) {
  return 1; // TODO: implement
}

int atclient_atkey_create_sharedkey(atclient_atkey *atkey, const char *name, const char *sharedby,
                                    const char *sharedwith, char *namespacestr) {
  return 1; // TODO: implement
}