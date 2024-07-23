#include "atclient/atkey.h"
#include "atclient/constants.h"
#include "atlogger/atlogger.h"
#include <stddef.h>
#include <stdlib.h>
#include <string.h>

#define TAG "test_atkey_create"

static int test1_create_publickey();
static int test2_create_selfkey();
static int test3_create_sharedkey();

int main() {
  int ret = 1;

  atlogger_set_logging_level(ATLOGGER_LOGGING_LEVEL_DEBUG);

  if ((ret = test1_create_publickey()) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "test1_create_publickey: %d\n", ret);
    goto exit;
  }

  if ((ret = test2_create_selfkey()) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "test2_create_selfkey: %d\n", ret);
    goto exit;
  }

  if ((ret = test3_create_sharedkey()) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "test3_create_sharedkey: %d\n", ret);
    goto exit;
  }

  ret = 0;
  goto exit;
exit: { return ret; }
}

static int test1_create_publickey() {
  int ret = 1;

  atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_DEBUG, "test1_create_publickey Begin\n");

  atclient_atkey atkey;
  atclient_atkey_init(&atkey);

  char *atkeystr = NULL;

  const char *expected = "public:test@alice";
  const size_t expectedlen = strlen(expected);

  if ((ret = atclient_atkey_create_public_key(&atkey, "test", "@alice", NULL)) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "Failed to create public key\n");
    goto exit;
  }

  const atclient_atkey_type atkey_type = atclient_atkey_get_type(&atkey);

  if (atkey_type != ATCLIENT_ATKEY_TYPE_PUBLIC_KEY) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atkey type is not ATCLIENT_ATKEY_TYPE_PUBLIC_KEY, it is %d\n",
                 atkey_type);
    ret = 1;
    goto exit;
  }

  if (!atclient_atkey_is_key_initialized(&atkey)) {
    ret = 1;
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atkey key is not initialized when it should be\n");
    goto exit;
  }

  if (strcmp(atkey.key, "test") != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atkey.key is not test, it is \"%s\"\n", atkey.key);
    ret = 1;
    goto exit;
  }

  if (!atclient_atkey_is_shared_by_initialized(&atkey)) {
    ret = 1;
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atkey shared_by is not initialized when it should be\n");
    goto exit;
  }

  if (strcmp(atkey.shared_by, "@alice") != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atkey.shared_by.str is not @alice, it is \"%s\"\n", atkey.shared_by);
    ret = 1;
    goto exit;
  }

  if ((ret = atclient_atkey_to_string(&atkey, &atkeystr)) != 0) {
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
exit: {
  atclient_atkey_free(&atkey);
  free(atkeystr);
  atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_DEBUG, "test1_create_publickey End: %d\n", ret);
  return ret;
}
}

static int test2_create_selfkey() {
  int ret = 1;

  atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_DEBUG, "test2_create_selfkey Begin\n");

  atclient_atkey atkey;
  atclient_atkey_init(&atkey);

  char *atkeystr = NULL;

  const char *expected = "name@jeremy";
  const size_t expectedlen = strlen(expected);

  ret = atclient_atkey_create_self_key(&atkey, "name", "@jeremy", NULL);
  if (ret != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atclient_atkey_create_self_key: %d\n", ret);
    goto exit;
  }

  const atclient_atkey_type atkey_type = atclient_atkey_get_type(&atkey);

  if (atkey_type != ATCLIENT_ATKEY_TYPE_SELF_KEY) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atkey type is not ATCLIENT_ATKEY_TYPE_SELF_KEY, it is %d\n",
                 atkey_type);
    ret = 1;
    goto exit;
  }

  if (!atclient_atkey_is_key_initialized(&atkey)) {
    ret = 1;
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atkey key is not initialized when it should be\n");
    goto exit;
  }

  if (strcmp(atkey.key, "name") != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atkey.key is not name, it is \"%s\"\n", atkey.key);
    ret = 1;
    goto exit;
  }

  if (!atclient_atkey_is_shared_by_initialized(&atkey)) {
    ret = 1;
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atkey shared_by is not initialized when it should be\n");
    goto exit;
  }

  if (strcmp(atkey.shared_by, "@jeremy") != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atkey.shared_by is not @jeremy, it is \"%s\"\n", atkey.shared_by);
    ret = 1;
    goto exit;
  }

  if ((ret = atclient_atkey_to_string(&atkey, &atkeystr)) != 0) {
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
    ret = 1;
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atkeystrolen is not %lu, it is %lu\n", expectedlen, atkeystrolen);
    goto exit;
  }

  ret = 0;
  goto exit;
exit: {
  free(atkeystr);
  atclient_atkey_free(&atkey);
  atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_DEBUG, "test2_create_selfkey End: %d\n", ret);
  return ret;
}
}

static int test3_create_sharedkey() {
  int ret = 1;

  atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_DEBUG, "test3_create_sharedkey Begin\n");

  atclient_atkey atkey;
  atclient_atkey_init(&atkey);

  char *atkeystr = NULL;

  const char *expected = "@jeremy:name.wavi@chess69lovely";
  const size_t expectedlen = strlen(expected);

  if ((ret = atclient_atkey_create_shared_key(&atkey, "name", "@chess69lovely", "@jeremy", "wavi")) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atclient_atkey_create_sharedkey: %d\n", ret);
    goto exit;
  }

  const atclient_atkey_type atkey_type = atclient_atkey_get_type(&atkey);

  if (atkey_type != ATCLIENT_ATKEY_TYPE_SHARED_KEY) {
    ret = 1;
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atkey type is not ATCLIENT_ATKEY_TYPE_SHARED_KEY, it is %d\n",
                 atkey_type);
    goto exit;
  }

  if(!atclient_atkey_is_key_initialized(&atkey)) {
    ret = 1;
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atkey key is not initialized when it should be\n");
    goto exit;
  }

  if (strcmp(atkey.key, "name") != 0) {
    ret = 1;
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atkey.key is not name, it is \"%s\"\n", atkey.key);
    goto exit;
  }

  if(!atclient_atkey_is_shared_by_initialized(&atkey)) {
    ret = 1;
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atkey shared_by is not initialized when it should be\n");
    goto exit;
  }

  if (strcmp(atkey.shared_by, "@chess69lovely") != 0) {
    ret = 1;
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atkey.shared_by is not @chess69lovely, it is \"%s\"\n", atkey.shared_by);
    goto exit;
  }

  if(!atclient_atkey_is_shared_with_initialized(&atkey)) {
    ret = 1;
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atkey shared_with is not initialized when it should be\n");
    goto exit;
  }

  if (strcmp(atkey.shared_with, "@jeremy") != 0) {
    ret = 1;
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atkey.shared_with is not @jeremy, it is \"%s\"\n",
                 atkey.shared_with);
    goto exit;
  }

  if(!atclient_atkey_is_namespacestr_initialized(&atkey)) {
    ret = 1;
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atkey namespace is not initialized when it should be\n");
    goto exit;
  }

  if (strcmp(atkey.namespace_str, "wavi") != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atkey.sharedwithname is not wavi, it is \"%s\"\n",
                 atkey.shared_with);
    ret = 1;
    goto exit;
  }

  if ((ret = atclient_atkey_to_string(&atkey, &atkeystr)) != 0) {
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
  atclient_atkey_free(&atkey);
  return ret;
}
}
