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
// 3A: private hidden key
#define TEST_ATKEY_FROM_STRING_3A "_lastnotificationid@alice123_4😘"

// Test 4: self keys
// 4A: self key with no namespace
#define TEST_ATKEY_FROM_STRING_4A "name@alice"
// 4B: self key with namespace
#define TEST_ATKEY_FROM_STRING_4B "name.wavi@jeremy_0"

// cached:public:publickey@bob
static int test1a() {
  int ret = 1;

  const char *atkeystr = TEST_ATKEY_FROM_STRING_1A;
  const size_t atkeystrlen = strlen(atkeystr);

  atclient_atkey atkey;
  atclient_atkey_init(&atkey);

  ret = atclient_atkey_from_string(&atkey, atkeystr, atkeystrlen);
  if (ret != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atclient_atkey_from_string failed\n");
    goto exit;
  }

  if (atkey.metadata.iscached != 1) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atkey.metadata.iscached is not 1\n");
    goto exit;
  }

  if (atkey.metadata.ispublic != 1) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atkey.metadata.ispublic is not 1, it is %d\n",
                 atkey.metadata.ispublic);
    goto exit;
  }

  if (atkey.atkeytype != ATCLIENT_ATKEY_TYPE_PUBLICKEY) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atkey.atkeytype is not ATCLIENT_ATKEY_TYPE_PUBLICKEY, it is %d\n",
                 atkey.atkeytype);
    goto exit;
  }

  if (strncmp(atkey.name.str, "publickey", atkey.name.len) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atkey.name is not publickey, it is \"%s\"\n", atkey.name.str);
    goto exit;
  }

  if (strncmp(atkey.sharedby.str, "@bob", atkey.sharedby.len) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atkey.sharedby is not @bob, it is \"%s\"\n", atkey.sharedby.str);
    goto exit;
  }
  ret = 0;
  goto exit;
exit: {
  return ret;
  atclient_atkey_free(&atkey);
}
}

static int test1b() {
  int ret = 1;

  const char *atkeystr = TEST_ATKEY_FROM_STRING_1B;
  const size_t atkeystrlen = strlen(atkeystr);

  atclient_atkey atkey;
  atclient_atkey_init(&atkey);

  ret = atclient_atkey_from_string(&atkey, atkeystr, atkeystrlen);
  if (ret != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atclient_atkey_from_string failed\n");
    goto exit;
  }

  if (atkey.metadata.iscached != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atkey.metadata.iscached is not 0\n");
    ret = 1;
    goto exit;
  }

  if (atkey.metadata.ispublic != 1) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atkey.metadata.ispublic is not 1, it is %d\n",
                 atkey.metadata.ispublic);
    ret = 1;
    goto exit;
  }

  if (atkey.atkeytype != ATCLIENT_ATKEY_TYPE_PUBLICKEY) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atkey.atkeytype is not ATCLIENT_ATKEY_TYPE_PUBLICKEY, it is %d\n",
                 atkey.atkeytype);
    ret = 1;
    goto exit;
  }

  if (strncmp(atkey.name.str, "publickey", atkey.name.len) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atkey.name is not publickey, it is \"%s\"\n", atkey.name.str);
    ret = 1;
    goto exit;
  }

  if (strncmp(atkey.sharedby.str, "@alice", atkey.sharedby.len) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atkey.sharedby is not @alice, it is \"%s\"\n", atkey.sharedby.str);
    ret = 1;
    goto exit;
  }

  if (atkey.namespacestr.len != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atkey.namespacestr.len is not 0, it is %lu\n",
                 atkey.namespacestr.len);
    ret = 1;
    goto exit;
  }

  if (atkey.sharedwith.len != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atkey.sharedwith.len is not 0, it is %lu\n", atkey.sharedwith.len);
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

static int test1c() {
  int ret = 1;

  const char *atkeystr = TEST_ATKEY_FROM_STRING_1C;
  const size_t atkeystrlen = strlen(atkeystr);

  atclient_atkey atkey;
  atclient_atkey_init(&atkey);

  ret = atclient_atkey_from_string(&atkey, atkeystr, atkeystrlen);
  if (ret != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atclient_atkey_from_string failed\n");
    goto exit;
  }

  if (atkey.metadata.iscached != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atkey.metadata.iscached is not 0\n");
    ret = 1;
    goto exit;
  }

  if (atkey.metadata.ispublic != 1) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atkey.metadata.ispublic is not 1, it is %d\n",
                 atkey.metadata.ispublic);
    ret = 1;
    goto exit;
  }

  if (atkey.atkeytype != ATCLIENT_ATKEY_TYPE_PUBLICKEY) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atkey.atkeytype is not ATCLIENT_ATKEY_TYPE_PUBLICKEY, it is %d\n",
                 atkey.atkeytype);
    ret = 1;
    goto exit;
  }

  if (strncmp(atkey.name.str, "name", atkey.name.len) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atkey.name is not name, it is \"%s\"\n", atkey.name.str);
    ret = 1;
    goto exit;
  }

  if (strncmp(atkey.sharedby.str, "@jeremy", atkey.sharedby.len) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atkey.sharedby is not @jeremy, it is \"%s\"\n",
                 atkey.sharedby.str);
    ret = 1;
    goto exit;
  }

  if (atkey.sharedwith.len != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atkey.sharedwith.len is not 0, it is %lu\n", atkey.sharedwith.len);
    ret = 1;
    goto exit;
  }

  if (strncmp(atkey.namespacestr.str, "wavi", atkey.namespacestr.len) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atkey.namespacestr is not wavi, it is \"%s\"\n",
                 atkey.namespacestr.str);
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

static int test1d() {
  int ret = 1;

  const char *atkeystr = TEST_ATKEY_FROM_STRING_1D;
  const size_t atkeystrlen = strlen(atkeystr);

  atclient_atkey atkey;
  atclient_atkey_init(&atkey);

  ret = atclient_atkey_from_string(&atkey, atkeystr, atkeystrlen);
  if (ret != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atclient_atkey_from_string failed\n");
    goto exit;
  }

  if (atkey.metadata.iscached != 1) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atkey.metadata.iscached is not 1\n");
    ret = 1;
    goto exit;
  }

  if (atkey.metadata.ispublic != 1) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atkey.metadata.ispublic is not 1, it is %d\n",
                 atkey.metadata.ispublic);
    ret = 1;
    goto exit;
  }

  if (atkey.atkeytype != ATCLIENT_ATKEY_TYPE_PUBLICKEY) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atkey.atkeytype is not ATCLIENT_ATKEY_TYPE_PUBLICKEY, it is %d\n",
                 atkey.atkeytype);
    ret = 1;
    goto exit;
  }

  if (strncmp(atkey.name.str, "name", atkey.name.len) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atkey.name is not name, it is \"%s\"\n", atkey.name.str);
    ret = 1;
    goto exit;
  }

  if (strncmp(atkey.sharedby.str, "@jeremy", atkey.sharedby.len) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atkey.sharedby is not @jeremy, it is \"%s\"\n",
                 atkey.sharedby.str);
    ret = 1;
    goto exit;
  }

  if (atkey.sharedwith.len != 0 && strlen(atkey.sharedwith.str) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atkey.sharedwith.len is not 0, it is %lu\n", atkey.sharedwith.len);
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atkey.sharedwith.str is not empty, it is \"%s\"\n",
                 atkey.sharedwith.str);
    ret = 1;
    goto exit;
  }

  if (strncmp(atkey.namespacestr.str, "wavi", atkey.namespacestr.len) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atkey.namespacestr is not wavi, it is \"%s\"\n",
                 atkey.namespacestr.str);
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

static int test2a() {
  int ret = 1;

  const char *atkeystr = TEST_ATKEY_FROM_STRING_2A;
  const size_t atkeystrlen = strlen(atkeystr);

  atclient_atkey atkey;
  atclient_atkey_init(&atkey);

  ret = atclient_atkey_from_string(&atkey, atkeystr, atkeystrlen);
  if (ret != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atclient_atkey_from_string failed\n");
    goto exit;
  }

  if (atkey.metadata.iscached != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atkey.metadata.iscached is not 0\n");
    ret = 1;
    goto exit;
  }

  if (atkey.metadata.ispublic != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atkey.metadata.ispublic is not 0, it is %d\n",
                 atkey.metadata.ispublic);
    ret = 1;
    goto exit;
  }

  if (atkey.atkeytype != ATCLIENT_ATKEY_TYPE_SHAREDKEY) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atkey.atkeytype is not ATCLIENT_ATKEY_TYPE_SHAREDKEY, it is %d\n",
                 atkey.atkeytype);
    ret = 1;
    goto exit;
  }

  if (strncmp(atkey.name.str, "name.wavi", atkey.name.len) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atkey.name is not name.wavi, it is \"%s\"\n", atkey.name.str);
    ret = 1;
    goto exit;
  }

  if (strncmp(atkey.sharedby.str, "@bob", atkey.sharedby.len) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atkey.sharedby is not @bob, it is \"%s\"\n", atkey.sharedby.str);
    ret = 1;
    goto exit;
  }

  if (strncmp(atkey.sharedwith.str, "@alice", atkey.sharedwith.len) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atkey.sharedwith is not @alice, it is \"%s\"\n",
                 atkey.sharedwith.str);
    ret = 1;
    goto exit;
  }

  if (strncmp(atkey.namespacestr.str, "wavi", atkey.namespacestr.len) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atkey.namespacestr is not wavi, it is \"%s\"\n",
                 atkey.namespacestr.str);
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

static int test2b() {
  int ret = 1;

  const char *atkeystr = TEST_ATKEY_FROM_STRING_2B;
  const size_t atkeystrlen = strlen(atkeystr);

  atclient_atkey atkey;
  atclient_atkey_init(&atkey);

  ret = atclient_atkey_from_string(&atkey, atkeystr, atkeystrlen);
  if (ret != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atclient_atkey_from_string failed\n");
    goto exit;
  }

  if (atkey.metadata.iscached != 1) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atkey.metadata.iscached is not 1\n");
    ret = 1;
    goto exit;
  }

  if (atkey.metadata.ispublic != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atkey.metadata.ispublic is not 0, it is %d\n",
                 atkey.metadata.ispublic);
    ret = 1;
    goto exit;
  }

  if (atkey.atkeytype != ATCLIENT_ATKEY_TYPE_SHAREDKEY) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atkey.atkeytype is not ATCLIENT_ATKEY_TYPE_SHAREDKEY, it is %d\n",
                 atkey.atkeytype);
    ret = 1;
    goto exit;
  }

  if (strncmp(atkey.name.str, "name", atkey.name.len) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atkey.name is not name, it is \"%s\"\n", atkey.name.str);
    ret = 1;
    goto exit;
  }

  if (strncmp(atkey.sharedby.str, "@alice", atkey.sharedby.len) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atkey.sharedby is not @alice, it is \"%s\"\n", atkey.sharedby.str);
    ret = 1;
    goto exit;
  }

  if (strncmp(atkey.sharedwith.str, "@bob", atkey.sharedwith.len) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atkey.sharedwith is not @bob, it is \"%s\"\n",
                 atkey.sharedwith.str);
    ret = 1;
    goto exit;
  }

  if (atkey.namespacestr.len != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atkey.namespacestr.len is not 0, it is %lu\n",
                 atkey.namespacestr.len);
    ret = 1;
    goto exit;
  }

  ret = 0;
  goto exit;
exit: { return ret; }
}

static int test2c() {
  int ret = 1;

  const char *atkeystr = TEST_ATKEY_FROM_STRING_2C;
  const size_t atkeystrlen = strlen(atkeystr);

  atclient_atkey atkey;
  atclient_atkey_init(&atkey);

  ret = atclient_atkey_from_string(&atkey, atkeystr, atkeystrlen);
  if (ret != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atclient_atkey_from_string failed\n");
    goto exit;
  }

  if (atkey.metadata.iscached != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atkey.metadata.iscached is not 0\n");
    ret = 1;
    goto exit;
  }

  if (atkey.metadata.ispublic != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atkey.metadata.ispublic is not 0, it is %d\n",
                 atkey.metadata.ispublic);
    ret = 1;
    goto exit;
  }

  if (atkey.atkeytype != ATCLIENT_ATKEY_TYPE_SHAREDKEY) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atkey.atkeytype is not ATCLIENT_ATKEY_TYPE_SHAREDKEY, it is %d\n",
                 atkey.atkeytype);
    ret = 1;
    goto exit;
  }

  if (strncmp(atkey.name.str, "name", atkey.name.len) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atkey.name is not name, it is \"%s\"\n", atkey.name.str);
    ret = 1;
    goto exit;
  }

  if (strncmp(atkey.sharedby.str, "@alice", atkey.sharedby.len) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atkey.sharedby is not @alice, it is \"%s\"\n", atkey.sharedby.str);
    ret = 1;
    goto exit;
  }

  if (strncmp(atkey.sharedwith.str, "@bob", atkey.sharedwith.len) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atkey.sharedwith is not @bob, it is \"%s\"\n",
                 atkey.sharedwith.str);
    ret = 1;
    goto exit;
  }

  if (atkey.namespacestr.len != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atkey.namespacestr.len is not 0, it is %lu\n",
                 atkey.namespacestr.len);
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

static int test2d() {
  int ret = 1;

  const char *atkeystr = TEST_ATKEY_FROM_STRING_2D;
  const size_t atkeystrlen = strlen(atkeystr);

  atclient_atkey atkey;
  atclient_atkey_init(&atkey);

  ret = atclient_atkey_from_string(&atkey, atkeystr, atkeystrlen);
  if (ret != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atclient_atkey_from_string failed\n");
    goto exit;
  }

  if (atkey.metadata.iscached != 1) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atkey.metadata.iscached is not 1\n");
    ret = 1;
    goto exit;
  }

  if (atkey.metadata.ispublic != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atkey.metadata.ispublic is not 0, it is %d\n",
                 atkey.metadata.ispublic);
    ret = 1;
    goto exit;
  }

  if (atkey.atkeytype != ATCLIENT_ATKEY_TYPE_SHAREDKEY) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atkey.atkeytype is not ATCLIENT_ATKEY_TYPE_SHAREDKEY, it is %d\n",
                 atkey.atkeytype);
    ret = 1;
    goto exit;
  }

  if (strncmp(atkey.name.str, "name", atkey.name.len) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atkey.name is not name, it is \"%s\"\n", atkey.name.str);
    ret = 1;
    goto exit;
  }

  if (strncmp(atkey.sharedby.str, "@alice", atkey.sharedby.len) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atkey.sharedby is not @alice, it is \"%s\"\n", atkey.sharedby.str);
    ret = 1;
    goto exit;
  }

  if (strncmp(atkey.sharedwith.str, "@bob", atkey.sharedwith.len) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atkey.sharedwith is not @bob, it is \"%s\"\n",
                 atkey.sharedwith.str);
    ret = 1;
    goto exit;
  }

  if (strncmp(atkey.namespacestr.str, "wavi", atkey.namespacestr.len) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atkey.namespacestr is not wavi, it is \"%s\"\n",
                 atkey.namespacestr.str);
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

static int test2e() {
  int ret = 1;

  atclient_atkey atkey;
  atclient_atkey_init(&atkey);

  if ((ret = atclient_atkey_from_string(&atkey, TEST_ATKEY_FROM_STRING_2E, strlen(TEST_ATKEY_FROM_STRING_2E))) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atclient_atkey_from_string failed: %d\n", ret);
    goto exit;
  }

  // @alice:name.vpsx.sshnp.abcd.efgh@xavierbob123
  if(strcmp(atkey.sharedby.str, "@xavierbob123") != 0) {
    ret = 1;
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atkey.sharedby is not @jeremy, it is %s\n", atkey.sharedby.str);
    goto exit;
  }

  if(strcmp(atkey.sharedwith.str, "@alice") != 0) {
    ret = 1;
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atkey.sharedwith is not @jeremy, it is %s\n", atkey.sharedwith.str);
    goto exit;
  }

  if(strcmp(atkey.name.str, "name") != 0) {
    ret = 1;
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atkey.name is not name, it is %s\n", atkey.name.str);
    goto exit;
  }

  if(strcmp(atkey.namespacestr.str, "vpsx.sshnp.abcd.efgh") != 0) {
    ret = 1;
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atkey.namespacestr is not vps1.sshnp, it is %s\n", atkey.namespacestr.str);
    goto exit;
  }

  ret = 0;
  goto exit;
exit: {
  atclient_atkey_free(&atkey);
  return ret;
}
}

static int test2f() {
  int ret = 1;

  atclient_atkey atkey;
  atclient_atkey_init(&atkey);

  if ((ret = atclient_atkey_from_string(&atkey, TEST_ATKEY_FROM_STRING_2F, strlen(TEST_ATKEY_FROM_STRING_2F))) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atclient_atkey_from_string failed: %d\n", ret);
    goto exit;
  }

  // cached:@jeremy:name.vps1.sshnp@xavier

  if(!atclient_atkey_metadata_is_iscached_initialized(&atkey.metadata)) {
    ret = 1;
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atkey.metadata.iscached is not initialized when it should be\n");
    goto exit;
  }

  if(atkey.metadata.iscached != true) {
    ret = 1;
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atkey.metadata.iscached is false when it should be true\n");
    goto exit;
  }

  if(strcmp(atkey.sharedby.str, "@xavier") != 0) {
    ret = 1;
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atkey.sharedby is not @jeremy, it is %s\n", atkey.sharedby.str);
    goto exit;
  }

  if(strcmp(atkey.sharedwith.str, "@jeremy") != 0) {
    ret = 1;
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atkey.sharedwith is not @jeremy, it is %s\n", atkey.sharedwith.str);
    goto exit;
  }

  if(strcmp(atkey.name.str, "name") != 0) {
    ret = 1;
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atkey.name is not name, it is %s\n", atkey.name.str);
    goto exit;
  }

  if(strcmp(atkey.namespacestr.str, "vps1.sshnp") != 0) {
    ret = 1;
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atkey.namespacestr is not vps1.sshnp, it is %s\n", atkey.namespacestr.str);
    goto exit;
  }

  ret = 0;
  goto exit;
exit: { return ret; }
}

static int test3a() {
  int ret = 1;

  const char *atkeystr = TEST_ATKEY_FROM_STRING_3A;
  const size_t atkeystrlen = strlen(atkeystr);

  atclient_atkey atkey;
  atclient_atkey_init(&atkey);

  ret = atclient_atkey_from_string(&atkey, atkeystr, atkeystrlen);
  if (ret != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atclient_atkey_from_string failed\n");
    goto exit;
  }

  if (atkey.metadata.iscached != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atkey.metadata.iscached is not 0\n");
    ret = 1;
    goto exit;
  }

  if (atkey.metadata.ispublic != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atkey.metadata.ispublic is not 0, it is %d\n",
                 atkey.metadata.ispublic);
    ret = 1;
    goto exit;
  }

  if (atkey.atkeytype != ATCLIENT_ATKEY_TYPE_SELFKEY) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR,
                 "atkey.atkeytype is not ATCLIENT_ATKEY_TYPE_PRIVATEHIDDENKEY, it is %d\n", atkey.atkeytype);
    ret = 1;
    goto exit;
  }

  if (strncmp(atkey.name.str, "_lastnotificationid", atkey.name.len) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atkey.name is not _lastnotificationid, it is \"%s\"\n",
                 atkey.name.str);
    ret = 1;
    goto exit;
  }

  if (strncmp(atkey.sharedby.str, "@alice123_4😘", atkey.sharedby.len) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atkey.sharedby is not @alice123_4😘, it is \"%s\"\n",
                 atkey.sharedby.str);
    ret = 1;
    goto exit;
  }

  if (atkey.sharedwith.len != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atkey.sharedwith.len is not 0, it is %lu\n", atkey.sharedwith.len);
    ret = 1;
    goto exit;
  }

  if (atkey.namespacestr.len != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atkey.namespacestr.len is not 0, it is %lu\n",
                 atkey.namespacestr.len);
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

static int test4a() {
  int ret = 1;

  const char *atkeystr = TEST_ATKEY_FROM_STRING_4A;
  const size_t atkeystrlen = strlen(atkeystr);

  atclient_atkey atkey;
  atclient_atkey_init(&atkey);

  ret = atclient_atkey_from_string(&atkey, atkeystr, atkeystrlen);
  if (ret != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atclient_atkey_from_string failed\n");
    goto exit;
  }

  if (atkey.metadata.iscached != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atkey.metadata.iscached is not 0\n");
    ret = 1;
    goto exit;
  }

  if (atkey.metadata.ispublic != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atkey.metadata.ispublic is not 0, it is %d\n",
                 atkey.metadata.ispublic);
    ret = 1;
    goto exit;
  }

  if (atkey.atkeytype != ATCLIENT_ATKEY_TYPE_SELFKEY) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atkey.atkeytype is not ATCLIENT_ATKEY_TYPE_SELFKEY, it is %d\n",
                 atkey.atkeytype);
    ret = 1;
    goto exit;
  }

  if (strncmp(atkey.name.str, "name", atkey.name.len) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atkey.name is not name, it is \"%s\"\n", atkey.name.str);
    ret = 1;
    goto exit;
  }

  if (strncmp(atkey.sharedby.str, "@alice", atkey.sharedby.len) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atkey.sharedby is not @alice, it is \"%s\"\n", atkey.sharedby.str);
    ret = 1;
    goto exit;
  }

  if (atkey.sharedwith.len != 0 && strlen(atkey.sharedwith.str) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atkey.sharedwith.len is not 0, it is %lu\n", atkey.sharedwith.len);
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atkey.sharedwith.str is not empty, it is \"%s\"\n",
                 atkey.sharedwith.str);
    ret = 1;
    goto exit;
  }

  if (atkey.namespacestr.len != 0 && strlen(atkey.namespacestr.str) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atkey.namespacestr.len is not 0, it is %lu\n",
                 atkey.namespacestr.len);
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atkey.namespacestr.str is not empty, it is \"%s\"\n",
                 atkey.namespacestr.str);
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

static int test4b() {
  int ret = 1;

  const char *atkeystr = TEST_ATKEY_FROM_STRING_4B;
  const size_t atkeystrlen = strlen(atkeystr);

  atclient_atkey atkey;
  atclient_atkey_init(&atkey);

  ret = atclient_atkey_from_string(&atkey, atkeystr, atkeystrlen);
  if (ret != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atclient_atkey_from_string failed\n");
    goto exit;
  }

  if (atkey.metadata.iscached != 0) {
    ret = 1;
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atkey.metadata.iscached is not 0\n");
    goto exit;
  }

  if (atkey.metadata.ispublic != 0) {
    ret = 1;
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atkey.metadata.ispublic is not 0, it is %d\n",
                 atkey.metadata.ispublic);
    goto exit;
  }

  if (atkey.atkeytype != ATCLIENT_ATKEY_TYPE_SELFKEY) {
    ret = 1;
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atkey.atkeytype is not ATCLIENT_ATKEY_TYPE_SELFKEY, it is %d\n",
                 atkey.atkeytype);
    goto exit;
  }

  if (strncmp(atkey.name.str, "name", atkey.name.len) != 0) {
    ret = 1;
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atkey.name is not name, it is \"%s\"\n", atkey.name.str);
    goto exit;
  }

  if (strncmp(atkey.sharedby.str, "@jeremy_0", atkey.sharedby.len) != 0) {
    ret = 1;
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atkey.sharedby is not @jeremy_0, it is \"%s\"\n",
                 atkey.sharedby.str);
    goto exit;
  }

  if (atkey.sharedwith.len != 0 && strlen(atkey.sharedwith.str) != 0) {
    ret = 1;
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atkey.sharedwith.len is not 0, it is %lu\n", atkey.sharedwith.len);
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atkey.sharedwith.str is not empty, it is \"%s\"\n",
                 atkey.sharedwith.str);
    goto exit;
  }

  if (strncmp(atkey.namespacestr.str, "wavi", atkey.namespacestr.len) != 0) {
    ret = 1;
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atkey.namespacestr is not wavi, it is \"%s\"\n",
                 atkey.namespacestr.str);
    goto exit;
  }

  ret = 0;
  goto exit;
exit: {
  atclient_atkey_free(&atkey);
  return ret;
}
}

int main() {
  int ret = 1;

  atlogger_set_logging_level(ATLOGGER_LOGGING_LEVEL_INFO);

  // test 1a. cached public key (cached:public:publickey@bob)
  if ((ret = test1a()) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "test1a failed\n");
    goto exit;
  }

  // test 1b. non-cached public key (public:publickey@alice)
  if ((ret = test1b()) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "test1b failed\n");
    goto exit;
  }

  // test 1c
  if ((ret = test1c()) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "test1c failed\n");
    goto exit;
  }

  // test 1d
  if ((ret = test1d()) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "test1d failed\n");
    goto exit;
  }

  // test 2a. non-cached sharedkey with namespace (@alice:name.wavi@bob)
  if ((ret = test2a()) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "test2a failed\n");
    goto exit;
  }

  if ((ret = test2b()) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "test2b failed\n");
    goto exit;
  }

  if ((ret = test2c()) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "test2c failed\n");
    goto exit;
  }

  if ((ret = test2d()) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "test2d failed\n");
    goto exit;
  }

  if ((ret = test2e()) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "test2e failed\n");
    goto exit;
  }

  if ((ret = test2f()) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "test2f failed\n");
    goto exit;
  }

  if ((ret = test3a()) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "test3a failed\n");
    goto exit;
  }

  if ((ret = test4a()) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "test4a failed\n");
    goto exit;
  }

  if ((ret = test4b()) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "test4b failed\n");
    goto exit;
  }

  ret = 0;
  goto exit;
exit: { return ret; }
}
