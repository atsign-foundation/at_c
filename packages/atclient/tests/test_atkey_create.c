#include "atclient/atkey.h"
#include "atclient/constants.h"
#include "atlogger/atlogger.h"
#include <stddef.h>
#include <stdlib.h>
#include <string.h>

#define TAG "test_atkey_create"

static int test_create_publickey() {
  int ret = 1;

  atclient_atkey atkey;
  atclient_atkey_init(&atkey);

  char *atkeystr = NULL;

  const char *expected = "public:test@alice";
  const size_t expectedlen = strlen(expected);

  ret = atclient_atkey_create_publickey(&atkey, "test", "@alice", NULL);
  if (ret != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "Failed to create public key\n");
    goto exit;
  }

  const atclient_atkey_type atkey_type = atclient_atkey_get_type(&atkey);

  if (atkey_type != ATCLIENT_ATKEY_TYPE_PUBLICKEY) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atkey type is not ATCLIENT_ATKEY_TYPE_PUBLICKEY, it is %d\n",
                 atkey_type);
    ret = 1;
    goto exit;
  }

  if (strcmp(atkey.key, "test") != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atkey.key is not test, it is \"%s\"\n", atkey.key);
    ret = 1;
    goto exit;
  }

  if (strcmp(atkey.sharedby, "@alice") != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atkey.sharedby.str is not @alice, it is \"%s\"\n", atkey.sharedby);
    ret = 1;
    goto exit;
  }

  ret = atclient_atkey_to_string(&atkey, &atkeystr);
  if (ret != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atclient_atkey_to_string: %d\n", ret);
    ret = 1;
    goto exit;
  }
  const size_t expectedolen = strlen(atkeystr);

  if (strcmp(atkeystr, expected) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atkeystr is not %s, it is %s\n", expected, atkeystr);
    ret = 1;
    goto exit;
  }

  if (expectedolen != expectedlen) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "expectedolen is not %lu, it is %lu\n", expectedlen, expectedolen);
    ret = 1;
    goto exit;
  }

  ret = 0;
  goto exit;
exit: {
  atclient_atkey_free(&atkey);
  free(atkeystr);
  return ret;
}
}

static int test_create_selfkey() {
  int ret = 1;

  atclient_atkey atkey;
  atclient_atkey_init(&atkey);

  char *atkeystr = NULL;

  const char *expected = "name@jeremy";
  const size_t expectedlen = strlen(expected);

  ret = atclient_atkey_create_selfkey(&atkey, "name", "@jeremy", NULL);
  if (ret != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atclient_atkey_create_selfkey: %d\n", ret);
    goto exit;
  }

  const atclient_atkey_type atkey_type = atclient_atkey_get_type(&atkey);

  if (atkey_type != ATCLIENT_ATKEY_TYPE_SELFKEY) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atkey type is not ATCLIENT_ATKEY_TYPE_SELFKEY, it is %d\n",
                 atkey_type);
    ret = 1;
    goto exit;
  }

  if (strcmp(atkey.key, "name") != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atkey.key is not name, it is \"%s\"\n", atkey.key);
    ret = 1;
    goto exit;
  }

  if (strcmp(atkey.sharedby, "@jeremy") != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atkey.sharedby is not @jeremy, it is \"%s\"\n", atkey.sharedby);
    ret = 1;
    goto exit;
  }

  ret = atclient_atkey_to_string(&atkey, &atkeystr);
  if (ret != 0) {
    ret = 1;
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atclient_atkey_to_string: %d\n", ret);
    goto exit;
  }
  const size_t atkeystrolen = strlen(atkeystr);

  if (strcmp(atkeystr, expected) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atkeystr is not %s, it is %s\n", expected, atkeystr);
    ret = 1;
    goto exit;
  }

  if (atkeystrolen != expectedlen) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atkeystrolen is not %lu, it is %lu\n", expectedlen, atkeystrolen);
    ret = 1;
    goto exit;
  }

  ret = 0;
  goto exit;
exit: {
  free(atkeystr);
  return ret;
}
}

static int test_create_sharedkey() {
  int ret = 1;

  atclient_atkey atkey;
  atclient_atkey_init(&atkey);

  char *atkeystr = NULL;

  const char *expected = "@jeremy:name.wavi@chess69lovely";
  const size_t expectedlen = strlen(expected);

  ret = atclient_atkey_create_sharedkey(&atkey, "name", "@jeremy", "@chess69lovely", "wavi");
  if (ret != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atclient_atkey_create_sharedkey: %d\n", ret);
    goto exit;
  }

  const atclient_atkey_type atkey_type = atclient_atkey_get_type(&atkey);

  if (atkey_type != ATCLIENT_ATKEY_TYPE_SHAREDKEY) {
    ret = 1;
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atkey type is not ATCLIENT_ATKEY_TYPE_SHAREDKEY, it is %d\n",
                 atkey_type);
    goto exit;
  }

  if (strcmp(atkey.key, "name") != 0) {
    ret = 1;
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atkey.key is not name, it is \"%s\"\n", atkey.key);
    goto exit;
  }

  if (strcmp(atkey.sharedby, "@jeremy") != 0) {
    ret = 1;
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atkey.sharedby is not @jeremy, it is \"%s\"\n", atkey.sharedby);
    goto exit;
  }

  if (strcmp(atkey.sharedwith, "@chess69lovely") != 0) {
    ret = 1;
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atkey.sharedwith is not @chess69lovely, it is \"%s\"\n",
                 atkey.sharedwith);
    goto exit;
  }

  if (strcmp(atkey.namespacestr, "wavi") != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atkey.sharedwithname is not wavi, it is \"%s\"\n",
                 atkey.sharedwith);
    ret = 1;
    goto exit;
  }

  ret = atclient_atkey_to_string(&atkey, &atkeystr);
  if (ret != 0) {
    ret = 1;
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atclient_atkey_to_string: %d\n", ret);
    goto exit;
  }
  const size_t atkeystrolen = strlen(atkeystr);

  if (strcmp(atkeystr, expected) != 0) {
    ret = 1;
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atkeystr is not %s, it is %s\n", expected, atkeystr);
    goto exit;
  }

  if (atkeystrolen != expectedlen) {
    ret = 1;
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atkeystrolen is not %lu, it is %lu\n", expectedlen, atkeystrolen);
    goto exit;
  }

  ret = 0;
  goto exit;
exit: {
  free(atkeystr);
  return ret;
}
}

int main() {
  int ret = 1;

  atlogger_set_logging_level(ATLOGGER_LOGGING_LEVEL_DEBUG);

  ret = test_create_publickey();
  if (ret != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "test_create_publickey: %d\n", ret);
    goto exit;
  }

  ret = 0;
  goto exit;
exit: { return ret; }
}
