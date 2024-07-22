#include "atclient/atkey.h"
#include "atlogger/atlogger.h"
#include <stdbool.h>
#include <stddef.h>
#include <string.h>

#define TAG "test_atkey_from_string"

// Test 1: public keys
// 1A: cached public key
#define TEST_ATKEY_FROM_STRING_1A "cached:public:publickey@bob"
// 1B: non-cached public key
#define TEST_ATKEY_FROM_STRING_1B "public:publickey@alice"
// 1C. non-cached public key with namespace
#define TEST_ATKEY_FROM_STRING_1C "public:name.wavi@jeremy"
// 1D. cached public key with namespace
#define TEST_ATKEY_FROM_STRING_1D "cached:public:name.wavi@jeremy"

// Test 2: shared keys
// 2A: non-cached shared key with namespace
#define TEST_ATKEY_FROM_STRING_2A "@alice:name.wavi@bob"
// 2B: cached shared key without namespace
#define TEST_ATKEY_FROM_STRING_2B "cached:@bob:name@alice"
// 2C: non-cached shared key without namespace
#define TEST_ATKEY_FROM_STRING_2C "@bob:name@alice"
// 2D: cached shared key with namespace
#define TEST_ATKEY_FROM_STRING_2D "cached:@bob:name.wavi@alice"
// 2E: non-cached shared key with compounding namespace
#define TEST_ATKEY_FROM_STRING_2E "@alice:name.vpsx.sshnp.abcd.efgh@xavierbob123"
// 2F: cached shared key with compounding namespace
#define TEST_ATKEY_FROM_STRING_2F "cached:@jeremy:name.vps1.sshnp@xavier"

// Test 3: private hidden keys
// 3A: private hidden key without namespace
#define TEST_ATKEY_FROM_STRING_3A "_lastnotificationid@alice123_4😘"

// Test 4: self keys
// 4A: self key with no namespace
#define TEST_ATKEY_FROM_STRING_4A "name@alice"
// 4B: self key with namespace
#define TEST_ATKEY_FROM_STRING_4B "name.wavi@jeremy_0"

static int test1a_cached_publickey_without_namespace();
static int test1b_publickey_without_namespace();
static int test1c_publickey_with_namespace();
static int test1d_cached_publickey_with_namespace();
static int test2a_sharedkey_with_namespace();
static int test2b_cached_sharedkey_without_namespace();
static int test2c_sharedkey_without_namespace();
static int test2d_cached_sharedkey_with_namespace();
static int test2e_sharedkey_with_compounding_namespace();
static int test2f_cached_sharedkey_with_compounding_namespace();
static int test3a_privatehiddenkey_without_namespace();
static int test4a_selfkey_without_namespace();
static int test4b_selfkey_with_namespace();

int main() {
  int ret = 1;

  atlogger_set_logging_level(ATLOGGER_LOGGING_LEVEL_INFO);

  if ((ret = test1a_cached_publickey_without_namespace()) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "test1a_cached_publickey_without_namespace failed\n");
    goto exit;
  }

  if ((ret = test1b_publickey_without_namespace()) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "test1b_publickey_without_namespace failed\n");
    goto exit;
  }

  if ((ret = test1c_publickey_with_namespace()) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "test1c_publickey_with_namespace failed\n");
    goto exit;
  }

  if ((ret = test1d_cached_publickey_with_namespace()) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "test1d_cached_publickey_with_namespace failed\n");
    goto exit;
  }

  if ((ret = test2a_sharedkey_with_namespace()) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "test2a_sharedkey_with_namespace failed\n");
    goto exit;
  }

  if ((ret = test2b_cached_sharedkey_without_namespace()) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "test2b_cached_sharedkey_without_namespace failed\n");
    goto exit;
  }

  if ((ret = test2c_sharedkey_without_namespace()) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "test2c_sharedkey_without_namespace failed\n");
    goto exit;
  }

  if ((ret = test2d_cached_sharedkey_with_namespace()) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "test2d_cached_sharedkey_with_namespace failed\n");
    goto exit;
  }

  if ((ret = test2e_sharedkey_with_compounding_namespace()) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "test2e_sharedkey_with_compounding_namespace failed\n");
    goto exit;
  }

  if ((ret = test2f_cached_sharedkey_with_compounding_namespace()) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "test2f_cached_sharedkey_with_compounding_namespace failed\n");
    goto exit;
  }

  if ((ret = test3a_privatehiddenkey_without_namespace()) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "test3a_privatehiddenkey_without_namespace failed\n");
    goto exit;
  }

  if ((ret = test4a_selfkey_without_namespace()) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "test4a_selfkey_without_namespace failed\n");
    goto exit;
  }

  if ((ret = test4b_selfkey_with_namespace()) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "test4b_selfkey_with_namespace failed\n");
    goto exit;
  }

  ret = 0;
  goto exit;
exit: { return ret; }
}

// cached:public:publickey@bob
static int test1a_cached_publickey_without_namespace() {
  int ret = 1;

  const char *atkeystr = TEST_ATKEY_FROM_STRING_1A;

  atclient_atkey atkey;
  atclient_atkey_init(&atkey);

  if ((ret = atclient_atkey_from_string(&atkey, atkeystr)) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atclient_atkey_from_string failed\n");
    goto exit;
  }

  if (atkey.metadata.iscached != true) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atkey.metadata.iscached is not 1\n");
    goto exit;
  }

  if (atkey.metadata.ispublic != true) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atkey.metadata.ispublic is not 1, it is %d\n",
                 atkey.metadata.ispublic);
    goto exit;
  }

  const atclient_atkey_type atkey_type = atclient_atkey_get_type(&atkey);

  if (atkey_type != ATCLIENT_ATKEY_TYPE_PUBLICKEY) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atkey.atkeytype is not ATCLIENT_ATKEY_TYPE_PUBLICKEY, it is %d\n",
                 atkey_type);
    goto exit;
  }

  if (strcmp(atkey.key, "publickey") != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atkey.name is not publickey, it is \"%s\"\n", atkey.key);
    goto exit;
  }

  if (strcmp(atkey.sharedby, "@bob") != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atkey.sharedby is not @bob, it is \"%s\"\n", atkey.sharedby);
    goto exit;
  }
  ret = 0;
  goto exit;
exit: {
  return ret;
  atclient_atkey_free(&atkey);
}
}

static int test1b_publickey_without_namespace() {
  int ret = 1;

  const char *atkeystr = TEST_ATKEY_FROM_STRING_1B;

  atclient_atkey atkey;
  atclient_atkey_init(&atkey);

  if ((ret = atclient_atkey_from_string(&atkey, atkeystr)) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atclient_atkey_from_string failed\n");
    goto exit;
  }


  if(!atclient_atkey_metadata_is_ispublic_initialized(&atkey.metadata)) {
    ret = 1;
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atkey.metadata.ispublic is not initialized\n");
    goto exit;
  }

  if (atkey.metadata.ispublic != true) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atkey.metadata.ispublic is not 1, it is %d\n",
                 atkey.metadata.ispublic);
    ret = 1;
    goto exit;
  }

  const atclient_atkey_type atkey_type = atclient_atkey_get_type(&atkey);

  if (atkey_type != ATCLIENT_ATKEY_TYPE_PUBLICKEY) {
    ret = 1;
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atkey.atkeytype is not ATCLIENT_ATKEY_TYPE_PUBLICKEY, it is %d\n",
                 atkey_type);
    goto exit;
  }

  if (!atclient_atkey_is_key_initialized(&atkey)) {
    ret = 1;
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atkey.key is not initialized when it should be\n");
    goto exit;
  }

  if (strcmp(atkey.key, "publickey") != 0) {
    ret = 1;
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atkey.name is not publickey, it is \"%s\"\n", atkey.key);
    goto exit;
  }

  if (!atclient_atkey_is_sharedby_initialized(&atkey)) {
    ret = 1;
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atkey.sharedby is not initialized when it should be\n");
    goto exit;
  }

  if (atclient_atkey_is_sharedby_initialized(&atkey) && strcmp(atkey.sharedby, "@alice") != 0) {
    ret = 1;
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atkey.sharedby is not @alice, it is \"%s\"\n", atkey.sharedby);
    goto exit;
  }

  if (atclient_atkey_is_namespacestr_initialized(&atkey)) {
    ret = 1;
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atkey.namespacestr is initialized when it should not be\n");
    goto exit;
  }

  if (atclient_atkey_is_sharedwith_initialized(&atkey)) {
    ret = 1;
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atkey.sharedwith is initialized when it should not be\n");
    goto exit;
  }

  ret = 0;
  goto exit;
exit: {
  atclient_atkey_free(&atkey);
  return ret;
}
}

static int test1c_publickey_with_namespace() {
  int ret = 1;

  const char *atkeystr = TEST_ATKEY_FROM_STRING_1C;

  atclient_atkey atkey;
  atclient_atkey_init(&atkey);

  if ((ret = atclient_atkey_from_string(&atkey, atkeystr)) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atclient_atkey_from_string failed\n");
    goto exit;
  }

  if (!atclient_atkey_metadata_is_ispublic_initialized(&atkey.metadata)) {
    ret = 1;
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atkey.metadata.ispublic is not initialized\n");
    goto exit;
  }

  if (atkey.metadata.ispublic != true) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atkey.metadata.ispublic is not 1, it is %d\n",
                 atkey.metadata.ispublic);
    ret = 1;
    goto exit;
  }

  const atclient_atkey_type atkey_type = atclient_atkey_get_type(&atkey);

  if (atkey_type != ATCLIENT_ATKEY_TYPE_PUBLICKEY) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atkey.atkeytype is not ATCLIENT_ATKEY_TYPE_PUBLICKEY, it is %d\n",
                 atkey_type);
    ret = 1;
    goto exit;
  }

  if (!atclient_atkey_is_key_initialized(&atkey)) {
    ret = 1;
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atkey.key is not initialized, when it should be\n");
    goto exit;
  }

  if (strcmp(atkey.key, "name") != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atkey.key is not name, it is \"%s\"\n", atkey.key);
    ret = 1;
    goto exit;
  }

  if (!atclient_atkey_is_sharedby_initialized(&atkey)) {
    ret = 1;
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atkey.sharedby is not initialized, when it should be\n");
    goto exit;
  }

  if (strcmp(atkey.sharedby, "@jeremy") != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atkey.sharedby is not @jeremy, it is \"%s\"\n", atkey.sharedby);
    ret = 1;
    goto exit;
  }
  if (!atclient_atkey_is_namespacestr_initialized(&atkey)) {
    ret = 1;
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atkey.namespacestr is not initialized, when it should be\n");
    goto exit;
  }

  if (strcmp(atkey.namespacestr, "wavi") != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atkey.namespacestr is not \'wavi\', it is \"%s\"\n",
                 atkey.namespacestr);
    ret = 1;
    goto exit;
  }

  if (atclient_atkey_is_sharedwith_initialized(&atkey)) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atkey.sharedwith is initialized, when it should not be\n");
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

static int test1d_cached_publickey_with_namespace() {
  int ret = 1;

  const char *atkeystr = TEST_ATKEY_FROM_STRING_1D;

  atclient_atkey atkey;
  atclient_atkey_init(&atkey);

  if ((ret = atclient_atkey_from_string(&atkey, atkeystr)) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atclient_atkey_from_string failed\n");
    goto exit;
  }

  if (!atclient_atkey_metadata_is_iscached_initialized(&atkey.metadata)) {
    ret = 1;
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atkey.metadata.iscached is not initialized\n");
    goto exit;
  }

  if (atkey.metadata.iscached != true) {
    ret = 1;
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atkey.metadata.iscached is not 1\n");
    goto exit;
  }

  if (!atclient_atkey_metadata_is_ispublic_initialized(&atkey.metadata)) {
    ret = 1;
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atkey.metadata.ispublic is not initialized\n");
    goto exit;
  }

  if (atkey.metadata.ispublic != true) {
    ret = 1;
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atkey.metadata.ispublic is not 1, it is %d\n",
                 atkey.metadata.ispublic);
    goto exit;
  }

  const atclient_atkey_type atkey_type = atclient_atkey_get_type(&atkey);

  if (atkey_type != ATCLIENT_ATKEY_TYPE_PUBLICKEY) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atkey.atkeytype is not ATCLIENT_ATKEY_TYPE_PUBLICKEY, it is %d\n",
                 atkey_type);
    ret = 1;
    goto exit;
  }

  if (!atclient_atkey_is_key_initialized(&atkey)) {
    ret = 1;
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atkey.key is not initialized, when it should be\n");
    goto exit;
  }

  if (strcmp(atkey.key, "name") != 0) {
    ret = 1;
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atkey.key is not name, it is \"%s\"\n", atkey.key);
    goto exit;
  }

  if (!atclient_atkey_is_sharedby_initialized(&atkey)) {
    ret = 1;
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atkey.sharedby is not initialized, when it should be\n");
    goto exit;
  }

  if (strcmp(atkey.sharedby, "@jeremy") != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atkey.sharedby is not @jeremy, it is \"%s\"\n", atkey.sharedby);
    ret = 1;
    goto exit;
  }

  if (!atclient_atkey_is_namespacestr_initialized(&atkey)) {
    ret = 1;
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atkey.namespacestr is not initialized, when it should be\n");
    goto exit;
  }

  if (strcmp(atkey.namespacestr, "wavi") != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atkey.namespacestr is not wavi, it is \"%s\"\n",
                 atkey.namespacestr);
    ret = 1;
    goto exit;
  }

  if (atclient_atkey_is_sharedwith_initialized(&atkey)) {
    ret = 1;
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atkey.sharedwith is initialized, when it should not be\n");
    goto exit;
  }

  ret = 0;
  goto exit;

exit: {
  atclient_atkey_free(&atkey);
  return ret;
}
}

static int test2a_sharedkey_with_namespace() {
  int ret = 1;

  const char *atkeystr = TEST_ATKEY_FROM_STRING_2A;

  atclient_atkey atkey;
  atclient_atkey_init(&atkey);

  if ((ret = atclient_atkey_from_string(&atkey, atkeystr)) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atclient_atkey_from_string failed\n");
    goto exit;
  }

  const atclient_atkey_type atkey_type = atclient_atkey_get_type(&atkey);

  if (atkey_type != ATCLIENT_ATKEY_TYPE_SHAREDKEY) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atkey_type is not ATCLIENT_ATKEY_TYPE_SHAREDKEY, it is %d\n",
                 atkey_type);
    ret = 1;
    goto exit;
  }

  if (!atclient_atkey_is_key_initialized(&atkey)) {
    ret = 1;
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atkey.key is not initialized, when it should be\n");
    goto exit;
  }

  if (strcmp(atkey.key, "name") != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atkey.name is not name, it is \"%s\"\n", atkey.key);
    ret = 1;
    goto exit;
  }

  if (!atclient_atkey_is_sharedby_initialized(&atkey)) {
    ret = 1;
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atkey.sharedby is not initialized, when it should be\n");
    goto exit;
  }

  if (strcmp(atkey.sharedby, "@bob") != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atkey.sharedby is not @bob, it is \"%s\"\n", atkey.sharedby);
    ret = 1;
    goto exit;
  }

  if (!atclient_atkey_is_namespacestr_initialized(&atkey)) {
    ret = 1;
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atkey.namespacestr is not initialized, when it should be\n");
    goto exit;
  }

  if (strcmp(atkey.sharedwith, "@alice") != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atkey.sharedwith is not @alice, it is \"%s\"\n", atkey.sharedwith);
    ret = 1;
    goto exit;
  }

  if (!atclient_atkey_is_sharedwith_initialized(&atkey)) {
    ret = 1;
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atkey.sharedwith is not initialized, when it should be\n");
    goto exit;
  }

  if (strcmp(atkey.namespacestr, "wavi") != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atkey.namespacestr is not wavi, it is \"%s\"\n",
                 atkey.namespacestr);
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

static int test2b_cached_sharedkey_without_namespace() {
  int ret = 1;

  const char *atkeystr = TEST_ATKEY_FROM_STRING_2B;

  atclient_atkey atkey;
  atclient_atkey_init(&atkey);

  if ((ret = atclient_atkey_from_string(&atkey, atkeystr)) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atclient_atkey_from_string failed\n");
    goto exit;
  }

  if (!atclient_atkey_metadata_is_iscached_initialized(&atkey.metadata)) {
    ret = 1;
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atkey.metadata.iscached is not initialized\n");
    goto exit;
  }

  if (atkey.metadata.iscached != true) {
    ret = 1;
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atkey.metadata.iscached is not 1\n");
    goto exit;
  }

  const atclient_atkey_type atkey_type = atclient_atkey_get_type(&atkey);

  if (atkey_type != ATCLIENT_ATKEY_TYPE_SHAREDKEY) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atkey_type is not ATCLIENT_ATKEY_TYPE_SHAREDKEY, it is %d\n",
                 atkey_type);
    ret = 1;
    goto exit;
  }

  if (!atclient_atkey_is_key_initialized(&atkey)) {
    ret = 1;
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atkey.key is not initialized, when it should be\n");
    goto exit;
  }

  if (strcmp(atkey.key, "name") != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atkey.key is not name, it is \"%s\"\n", atkey.key);
    ret = 1;
    goto exit;
  }

  if (!atclient_atkey_is_sharedby_initialized(&atkey)) {
    ret = 1;
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atkey.sharedby is not initialized, when it should be\n");
    goto exit;
  }

  if (strcmp(atkey.sharedby, "@alice") != 0) {
    ret = 1;
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atkey.sharedby is not @alice, it is \"%s\"\n", atkey.sharedby);
    goto exit;
  }

  if (!atclient_atkey_is_sharedwith_initialized(&atkey)) {
    ret = 1;
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atkey.sharedwith is not initialized, when it should be\n");
    goto exit;
  }

  if (strcmp(atkey.sharedwith, "@bob") != 0) {
    ret = 1;
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atkey.sharedwith is not @bob, it is \"%s\"\n", atkey.sharedwith);
    goto exit;
  }

  if (atclient_atkey_is_namespacestr_initialized(&atkey)) {
    ret = 1;
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR,
                 "atkey.namespacestr is initialized when it is not supposed to be\n");
    goto exit;
  }

  ret = 0;
  goto exit;
exit: {
  atclient_atkey_free(&atkey);
  return ret;
}
}

static int test2c_sharedkey_without_namespace() {
  int ret = 1;

  const char *atkeystr = TEST_ATKEY_FROM_STRING_2C;

  atclient_atkey atkey;
  atclient_atkey_init(&atkey);

  if ((ret = atclient_atkey_from_string(&atkey, atkeystr)) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atclient_atkey_from_string failed\n");
    goto exit;
  }

  const atclient_atkey_type atkey_type = atclient_atkey_get_type(&atkey);

  if (atkey_type != ATCLIENT_ATKEY_TYPE_SHAREDKEY) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atkey_type is not ATCLIENT_ATKEY_TYPE_SHAREDKEY, it is %d\n",
                 atkey_type);
    ret = 1;
    goto exit;
  }

  if (!atclient_atkey_is_key_initialized(&atkey)) {
    ret = 1;
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atkey.key is not initialized, when it should be\n");
    goto exit;
  }

  if (strcmp(atkey.key, "name") != 0) {
    ret = 1;
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atkey.name is not name, it is \"%s\"\n", atkey.key);
    goto exit;
  }

  if (!atclient_atkey_is_sharedby_initialized(&atkey)) {
    ret = 1;
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atkey.sharedby is not initialized, when it should be\n");
    goto exit;
  }

  if (strcmp(atkey.sharedby, "@alice") != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atkey.sharedby is not @alice, it is \"%s\"\n", atkey.sharedby);
    ret = 1;
    goto exit;
  }

  if (!atclient_atkey_is_sharedwith_initialized(&atkey)) {
    ret = 1;
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atkey.sharedwith is not initialized, when it should be\n");
    goto exit;
  }

  if (strcmp(atkey.sharedwith, "@bob") != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atkey.sharedwith is not @bob, it is \"%s\"\n", atkey.sharedwith);
    ret = 1;
    goto exit;
  }

  if (atclient_atkey_is_namespacestr_initialized(&atkey)) {
    ret = 1;
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR,
                 "atkey.namespacestr is initialized when it is not supposed to be\n");
    goto exit;
  }

  ret = 0;
  goto exit;
exit: {
  atclient_atkey_free(&atkey);
  return ret;
}
}

static int test2d_cached_sharedkey_with_namespace() {
  int ret = 1;

  const char *atkeystr = TEST_ATKEY_FROM_STRING_2D;

  atclient_atkey atkey;
  atclient_atkey_init(&atkey);

  if ((ret = atclient_atkey_from_string(&atkey, atkeystr)) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atclient_atkey_from_string failed\n");
    goto exit;
  }

  if (!atclient_atkey_metadata_is_iscached_initialized(&atkey.metadata)) {
    ret = 1;
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atkey.metadata.iscached is not initialized\n");
    goto exit;
  }

  if (atkey.metadata.iscached != true) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atkey.metadata.iscached is not 1\n");
    ret = 1;
    goto exit;
  }

  const atclient_atkey_type atkey_type = atclient_atkey_get_type(&atkey);

  if (atkey_type != ATCLIENT_ATKEY_TYPE_SHAREDKEY) {
    ret = 1;
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atkey_type is not ATCLIENT_ATKEY_TYPE_SHAREDKEY, it is %d\n",
                 atkey_type);
    goto exit;
  }

  if (!atclient_atkey_is_key_initialized(&atkey)) {
    ret = 1;
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atkey.key is not initialized, when it should be\n");
    goto exit;
  }

  if (strcmp(atkey.key, "name") != 0) {
    ret = 1;
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atkey.key is not name, it is \"%s\"\n", atkey.key);
    goto exit;
  }

  if (!atclient_atkey_is_sharedby_initialized(&atkey)) {
    ret = 1;
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atkey.sharedby is not initialized, when it should be\n");
    goto exit;
  }

  if (strcmp(atkey.sharedby, "@alice") != 0) {
    ret = 1;
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atkey.sharedby is not @alice, it is \"%s\"\n", atkey.sharedby);
    goto exit;
  }

  if (!atclient_atkey_is_sharedwith_initialized(&atkey)) {
    ret = 1;
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atkey.sharedwith is not initialized, when it should be\n");
    goto exit;
  }

  if (strcmp(atkey.sharedwith, "@bob") != 0) {
    ret = 1;
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atkey.sharedwith is not @bob, it is \"%s\"\n", atkey.sharedwith);
    goto exit;
  }

  if (!atclient_atkey_is_namespacestr_initialized(&atkey)) {
    ret = 1;
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atkey.namespacestr is not initialized, when it should be\n");
    goto exit;
  }

  if (strcmp(atkey.namespacestr, "wavi") != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atkey.namespacestr is not wavi, it is \"%s\"\n",
                 atkey.namespacestr);
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

static int test2e_sharedkey_with_compounding_namespace() {
  int ret = 1;

  atclient_atkey atkey;
  atclient_atkey_init(&atkey);

  if ((ret = atclient_atkey_from_string(&atkey, TEST_ATKEY_FROM_STRING_2E)) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atclient_atkey_from_string failed: %d\n", ret);
    goto exit;
  }

  if(!atclient_atkey_is_sharedby_initialized(&atkey)) {
    ret = 1;
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atkey.sharedby is not initialized when it should be\n");
    goto exit;
  }

  if (strcmp(atkey.sharedby, "@xavierbob123") != 0) {
    ret = 1;
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atkey.sharedby is not @jeremy, it is %s\n", atkey.sharedby);
    goto exit;
  }

  if (!atclient_atkey_is_sharedwith_initialized(&atkey)) {
    ret = 1;
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atkey.sharedwith is not initialized when it should be\n");
    goto exit;
  }

  if (strcmp(atkey.sharedwith, "@alice") != 0) {
    ret = 1;
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atkey.sharedwith is not @jeremy, it is %s\n", atkey.sharedwith);
    goto exit;
  }

  if (!atclient_atkey_is_key_initialized(&atkey)) {
    ret = 1;
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atkey.key is not initialized when it should be\n");
    goto exit;
  }

  if (strcmp(atkey.key, "name") != 0) {
    ret = 1;
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atkey.key is not name, it is %s\n", atkey.key);
    goto exit;
  }

  if (!atclient_atkey_is_namespacestr_initialized(&atkey)) {
    ret = 1;
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atkey.namespacestr is not initialized when it should be\n");
    goto exit;
  }

  if (strcmp(atkey.namespacestr, "vpsx.sshnp.abcd.efgh") != 0) {
    ret = 1;
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atkey.namespacestr is not vps1.sshnp, it is %s\n",
                 atkey.namespacestr);
    goto exit;
  }

  ret = 0;
  goto exit;
exit: {
  atclient_atkey_free(&atkey);
  return ret;
}
}

static int test2f_cached_sharedkey_with_compounding_namespace() {
  int ret = 1;

  atclient_atkey atkey;
  atclient_atkey_init(&atkey);

  if ((ret = atclient_atkey_from_string(&atkey, TEST_ATKEY_FROM_STRING_2F)) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atclient_atkey_from_string failed: %d\n", ret);
    goto exit;
  }

  if (!atclient_atkey_metadata_is_iscached_initialized(&atkey.metadata)) {
    ret = 1;
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atkey.metadata.iscached is not initialized when it should be\n");
    goto exit;
  }

  if (atkey.metadata.iscached != true) {
    ret = 1;
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atkey.metadata.iscached is false when it should be true\n");
    goto exit;
  }

  if (!atclient_atkey_is_sharedby_initialized(&atkey)) {
    ret = 1;
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atkey.sharedby is not initialized when it should be\n");
    goto exit;
  }

  if (strcmp(atkey.sharedby, "@xavier") != 0) {
    ret = 1;
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atkey.sharedby is not @jeremy, it is %s\n", atkey.sharedby);
    goto exit;
  }

  if (!atclient_atkey_is_sharedwith_initialized(&atkey)) {
    ret = 1;
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atkey.sharedwith is not initialized when it should be\n");
    goto exit;
  }

  if (strcmp(atkey.sharedwith, "@jeremy") != 0) {
    ret = 1;
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atkey.sharedwith is not @jeremy, it is %s\n", atkey.sharedwith);
    goto exit;
  }

  if (!atclient_atkey_is_key_initialized(&atkey)) {
    ret = 1;
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atkey.key is not initialized when it should be\n");
    goto exit;
  }

  if (strcmp(atkey.key, "name") != 0) {
    ret = 1;
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atkey.name is not name, it is %s\n", atkey.key);
    goto exit;
  }

  if (!atclient_atkey_is_namespacestr_initialized(&atkey)) {
    ret = 1;
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atkey.namespacestr is not initialized when it should be\n");
    goto exit;
  }

  if (strcmp(atkey.namespacestr, "vps1.sshnp") != 0) {
    ret = 1;
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atkey.namespacestr is not vps1.sshnp, it is %s\n",
                 atkey.namespacestr);
    goto exit;
  }

  ret = 0;
  goto exit;
exit: {
  atclient_atkey_free(&atkey);
  return ret;
}
}

static int test3a_privatehiddenkey_without_namespace() {
  int ret = 1;

  const char *atkeystr = TEST_ATKEY_FROM_STRING_3A;

  atclient_atkey atkey;
  atclient_atkey_init(&atkey);

  if ((ret = atclient_atkey_from_string(&atkey, atkeystr)) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atclient_atkey_from_string failed\n");
    goto exit;
  }

  const atclient_atkey_type atkey_type = atclient_atkey_get_type(&atkey);

  if (atkey_type != ATCLIENT_ATKEY_TYPE_SELFKEY) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR,
                 "atkey_type is not ATCLIENT_ATKEY_TYPE_PRIVATEHIDDENKEY, it is %d\n", atkey_type);
    ret = 1;
    goto exit;
  }

  if(!atclient_atkey_is_key_initialized(&atkey)) {
    ret = 1;
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atkey.key is not initialized, when it should be\n");
    goto exit;
  }

  if (strcmp(atkey.key, "_lastnotificationid") != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atkey.key is not _lastnotificationid, it is \"%s\"\n", atkey.key);
    ret = 1;
    goto exit;
  }

  if(!atclient_atkey_is_sharedby_initialized(&atkey)) {
    ret = 1;
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atkey.sharedby is not initialized, when it should be\n");
    goto exit;
  }

  if (strcmp(atkey.sharedby, "@alice123_4😘") != 0) {
    ret = 1;
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atkey.sharedby is not @alice123_4😘, it is \"%s\"\n",
                 atkey.sharedby);
    goto exit;
  }

  if (atclient_atkey_is_sharedwith_initialized(&atkey)) {
    ret = 1;
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atkey.sharedwith is initialized when it should not be\n");
    goto exit;
  }

  if (atclient_atkey_is_namespacestr_initialized(&atkey)) {
    ret = 1;
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atkey.namespacestr is initialized when it should not be\n");
    goto exit;
  }

  ret = 0;
  goto exit;

exit: {
  atclient_atkey_free(&atkey);
  return ret;
}
}

static int test4a_selfkey_without_namespace() {
  int ret = 1;

  const char *atkeystr = TEST_ATKEY_FROM_STRING_4A;

  atclient_atkey atkey;
  atclient_atkey_init(&atkey);

  if ((ret = atclient_atkey_from_string(&atkey, atkeystr)) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atclient_atkey_from_string failed\n");
    goto exit;
  }

  const atclient_atkey_type atkey_type = atclient_atkey_get_type(&atkey);

  if (atkey_type != ATCLIENT_ATKEY_TYPE_SELFKEY) {
    ret = 1;
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atkey_type is not ATCLIENT_ATKEY_TYPE_SELFKEY, it is %d\n",
                 atkey_type);
    goto exit;
  }

  if(!atclient_atkey_is_key_initialized(&atkey)) {
    ret = 1;
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atkey.key is not initialized, when it should be\n");
    goto exit;
  }

  if (strcmp(atkey.key, "name") != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atkey.key is not name, it is \"%s\"\n", atkey.key);
    ret = 1;
    goto exit;
  }

  if(!atclient_atkey_is_sharedby_initialized(&atkey)) {
    ret = 1;
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atkey.sharedby is not initialized, when it should be\n");
    goto exit;
  }

  if (strcmp(atkey.sharedby, "@alice") != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atkey.sharedby is not @alice, it is \"%s\"\n", atkey.sharedby);
    ret = 1;
    goto exit;
  }

  if(atclient_atkey_is_sharedwith_initialized(&atkey)) {
    ret = 1;
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atkey.sharedwith is initialized when it should not be\n");
    goto exit;
  }

  if (atclient_atkey_is_namespacestr_initialized(&atkey)) {
    ret = 1;
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atkey.namespacestr is initialized when it should not be\n");
    goto exit;
  }

  ret = 0;
  goto exit;
exit: {
  atclient_atkey_free(&atkey);
  return ret;
}
}

static int test4b_selfkey_with_namespace() {
  int ret = 1;

  const char *atkeystr = TEST_ATKEY_FROM_STRING_4B;

  atclient_atkey atkey;
  atclient_atkey_init(&atkey);

  if ((ret = atclient_atkey_from_string(&atkey, atkeystr)) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atclient_atkey_from_string failed\n");
    goto exit;
  }
  const atclient_atkey_type atkey_type = atclient_atkey_get_type(&atkey);

  if (atkey_type != ATCLIENT_ATKEY_TYPE_SELFKEY) {
    ret = 1;
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atkey_type is not ATCLIENT_ATKEY_TYPE_SELFKEY, it is %d\n",
                 atkey_type);
    goto exit;
  }

  if(!atclient_atkey_is_key_initialized(&atkey)) {
    ret = 1;
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atkey.key is not initialized, when it should be\n");
    goto exit;
  }

  if (strcmp(atkey.key, "name") != 0) {
    ret = 1;
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atkey.key is not name, it is \"%s\"\n", atkey.key);
    goto exit;
  }

  if(!atclient_atkey_is_sharedby_initialized(&atkey)) {
    ret = 1;
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atkey.sharedby is not initialized, when it should be\n");
    goto exit;
  }

  if (strcmp(atkey.sharedby, "@jeremy_0") != 0) {
    ret = 1;
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atkey.sharedby is not @jeremy_0, it is \"%s\"\n", atkey.sharedby);
    goto exit;
  }

  if(!atclient_atkey_is_namespacestr_initialized(&atkey)) {
    ret = 1;
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atkey.namespacestr is not initialized, when it should be\n");
    goto exit;
  }

  if (strcmp(atkey.namespacestr, "wavi") != 0) {
    ret = 1;
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atkey.namespacestr is not wavi, it is \"%s\"\n",
                 atkey.namespacestr);
    goto exit;
  }

  if (atclient_atkey_is_sharedwith_initialized(&atkey)) {
    ret = 1;
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atkey.sharedwith is initialized when it should not be\n");
    goto exit;
  }

  ret = 0;
  goto exit;
exit: {
  atclient_atkey_free(&atkey);
  return ret;
}
}
