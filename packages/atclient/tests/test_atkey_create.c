#include "atclient/atkey.h"
#include "atclient/constants.h"
#include "atlogger/atlogger.h"
#include <string.h>
#include <stddef.h>

#define TAG "test_atkey_create"

static int test_create_publickey() {
  int ret = 1;

  atclient_atkey atkey;
  atclient_atkey_init(&atkey);

  char atkeystr[ATCLIENT_ATKEY_FULL_LEN + 1];
  memset(atkeystr, 0, ATCLIENT_ATKEY_FULL_LEN + 1);

  const char *expected = "public:test@alice";
  const size_t expectedlen = strlen(expected);
  size_t expectedolen = 0;

  ret = atclient_atkey_create_publickey(&atkey, "test", strlen("test"), "@alice", strlen("@alice"), NULL, 0);
  if (ret != 0) {
    atclient_atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "Failed to create public key\n");
    goto exit;
  }

  if (atkey.atkeytype != ATCLIENT_ATKEY_TYPE_PUBLICKEY) {
    atclient_atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR,
                          "atkey type is not ATCLIENT_ATKEY_TYPE_PUBLICKEY, it is %d\n", atkey.atkeytype);
    ret = 1;
    goto exit;
  }

  if (strcmp(atkey.name.str, "test") != 0) {
    atclient_atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atkey.name.str is not test, it is \"%s\"\n",
                          atkey.name.str);
    ret = 1;
    goto exit;
  }

  if (strcmp(atkey.sharedby.str, "@alice") != 0) {
    atclient_atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atkey.sharedby.str is not @alice, it is \"%s\"\n",
                          atkey.sharedby.str);
    ret = 1;
    goto exit;
  }

  ret = atclient_atkey_to_string(atkey, atkeystr, ATCLIENT_ATKEY_FULL_LEN, &expectedolen);
  if (ret != 0) {
    atclient_atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atclient_atkey_to_string: %d\n", ret);
    ret = 1;
    goto exit;
  }

  if (strcmp(atkeystr, expected) != 0) {
    atclient_atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atkeystr is not %s, it is %s\n", expected, atkeystr);
    ret = 1;
    goto exit;
  }

  if (expectedolen != expectedlen) {
    atclient_atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "expectedolen is not %lu, it is %lu\n", expectedlen,
                          expectedolen);
    ret = 1;
    goto exit;
  }

  ret = 0;
  goto exit;
exit: {
  atclient_atkey_free(&atkey);
  return ret;
}
}

static int test_create_selfkey() {
  int ret = 1;

  atclient_atkey atkey;
  atclient_atkey_init(&atkey);

  char atkeystr[ATCLIENT_ATKEY_FULL_LEN];
  memset(atkeystr, 0, ATCLIENT_ATKEY_FULL_LEN);

  const char *expected = "name@jeremy";
  const size_t expectedlen = strlen(expected);

  ret = atclient_atkey_create_selfkey(&atkey, "name", strlen("name"), "@jeremy", strlen("@jeremy"), NULL, 0);
  if (ret != 0) {
    atclient_atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atclient_atkey_create_selfkey: %d\n", ret);
    goto exit;
  }

  if (atkey.atkeytype != ATCLIENT_ATKEY_TYPE_SELFKEY) {
    atclient_atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR,
                          "atkey type is not ATCLIENT_ATKEY_TYPE_SELFKEY, it is %d\n", atkey.atkeytype);
    ret = 1;
    goto exit;
  }

  if (strcmp(atkey.name.str, "name") != 0) {
    atclient_atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atkey.name.str is not name, it is \"%s\"\n",
                          atkey.name.str);
    ret = 1;
    goto exit;
  }

  if (strcmp(atkey.sharedby.str, "@jeremy") != 0) {
    atclient_atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atkey.sharedby.str is not @jeremy, it is \"%s\"\n",
                          atkey.sharedby.str);
    ret = 1;
    goto exit;
  }

  size_t atkeystrolen = 0;
  ret = atclient_atkey_to_string(atkey, atkeystr, ATCLIENT_ATKEY_FULL_LEN, &atkeystrolen);
  if (ret != 0) {
    atclient_atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atclient_atkey_to_string: %d\n", ret);
    ret = 1;
    goto exit;
  }

  if (strcmp(atkeystr, expected) != 0) {
    atclient_atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atkeystr is not %s, it is %s\n", expected, atkeystr);
    ret = 1;
    goto exit;
  }

  if (atkeystrolen != expectedlen) {
    atclient_atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atkeystrolen is not %lu, it is %lu\n", expectedlen,
                          atkeystrolen);
    ret = 1;
    goto exit;
  }

  ret = 0;
  goto exit;
exit: { return ret; }
}

static int test_create_sharedkey() {
  int ret = 1;

  atclient_atkey atkey;
  atclient_atkey_init(&atkey);

  char atkeystr[ATCLIENT_ATKEY_FULL_LEN];
  memset(atkeystr, 0, ATCLIENT_ATKEY_FULL_LEN);

  const char *expected = "@jeremy:name.wavi@chess69lovely";
  const size_t expectedlen = strlen(expected);

  ret = atclient_atkey_create_sharedkey(&atkey, "name", strlen("name"), "@jeremy", strlen("@jeremy"), "@chess69lovely",
                                        strlen("@chess69lovely"), "wavi", strlen("wavi"));
  if (ret != 0) {
    atclient_atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atclient_atkey_create_sharedkey: %d\n", ret);
    goto exit;
  }

  if (atkey.atkeytype != ATCLIENT_ATKEY_TYPE_SHAREDKEY) {
    atclient_atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR,
                          "atkey type is not ATCLIENT_ATKEY_TYPE_SHAREDKEY, it is %d\n", atkey.atkeytype);
    ret = 1;
    goto exit;
  }

  if (strcmp(atkey.name.str, "name") != 0) {
    atclient_atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atkey.name.str is not name, it is \"%s\"\n",
                          atkey.name.str);
    ret = 1;
    goto exit;
  }

  if (strcmp(atkey.sharedby.str, "@jeremy") != 0) {
    atclient_atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atkey.sharedby.str is not @jeremy, it is \"%s\"\n",
                          atkey.sharedby.str);
    ret = 1;
    goto exit;
  }

  if (strcmp(atkey.sharedwith.str, "@chess69lovely") != 0) {
    atclient_atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR,
                          "atkey.sharedwith.str is not @chess69lovely, it is \"%s\"\n", atkey.sharedwith.str);
    ret = 1;
    goto exit;
  }

  if (strcmp(atkey.namespacestr.str, "wavi") != 0) {
    atclient_atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atkey.sharedwithname.str is not wavi, it is \"%s\"\n",
                          atkey.sharedwith.str);
    ret = 1;
    goto exit;
  }

  size_t atkeystrolen = 0;
  ret = atclient_atkey_to_string(atkey, atkeystr, ATCLIENT_ATKEY_FULL_LEN, &atkeystrolen);
  if (ret != 0) {
    atclient_atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atclient_atkey_to_string: %d\n", ret);
    ret = 1;
    goto exit;
  }

  if (strcmp(atkeystr, expected) != 0) {
    atclient_atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atkeystr is not %s, it is %s\n", expected, atkeystr);
    ret = 1;
    goto exit;
  }

  if (atkeystrolen != expectedlen) {
    atclient_atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atkeystrolen is not %lu, it is %lu\n", expectedlen,
                          atkeystrolen);
    ret = 1;
    goto exit;
  }

  ret = 0;
  goto exit;
exit: { return ret; }
}

int main() {
  int ret = 1;

  atclient_atlogger_set_logging_level(ATLOGGER_LOGGING_LEVEL_DEBUG);

  ret = test_create_publickey();
  if (ret != 0) {
    atclient_atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "test_create_publickey: %d\n", ret);
    goto exit;
  }

  ret = 0;
  goto exit;
exit: { return ret; }
}
