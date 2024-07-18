#include "atclient/atkey.h"
#include "atclient/constants.h"
#include "atlogger/atlogger.h"
#include <stdbool.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>

#define TAG "test_atkey_to_string"

// Test 1: public keys
// 1A: cached public key
#define TEST_ATKEY_TO_STRING_1A "cached:public:publickey@bob"
// 1B: non-cached public key
#define TEST_ATKEY_TO_STRING_1B "public:publickey@alice"
// 1C. non-cached public key with namespace
#define TEST_ATKEY_TO_STRING_1C "public:name.wavi@jeremy"
// 1D. cached public key with namespace
#define TEST_ATKEY_TO_STRING_1D "cached:public:name.wavi@jeremy"
// Test 2: shared keys
// 2A: non-cached shared key with namespace
#define TEST_ATKEY_TO_STRING_2A "@alice:name.wavi@bob"
// 2B: cached shared key without namespace
#define TEST_ATKEY_TO_STRING_2B "cached:@bob:name@alice"
// 2C: non-cached shared key without namespace
#define TEST_ATKEY_TO_STRING_2C "@bob:name@alice"
// 2D: cached shared key with namespace
#define TEST_ATKEY_TO_STRING_2D "cached:@bob:name.wavi@alice"
// Test 3: private hidden keys
// 3A: private hidden key
#define TEST_ATKEY_TO_STRING_3A "_lastnotificationid@alice123_4😘"
// Test 4: self keys
// 4A: self key with no namespace
#define TEST_ATKEY_TO_STRING_4A "name@alice"
// 4B: self key with namespace
#define TEST_ATKEY_TO_STRING_4B "name.wavi@jeremy_0"

static int test1a();
static int test1b();
static int test1c();
static int test1d();
static int test2a();
static int test2b();
static int test2c();
static int test2d();
static int test3a();
static int test4a();
static int test4b();

int main() {
  int ret = 1;

  atlogger_set_logging_level(ATLOGGER_LOGGING_LEVEL_DEBUG);

  ret = test1a();
  if (ret != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "test1a failed\n");
    goto exit;
  }

  ret = test1b();
  if (ret != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "test1b failed\n");
    goto exit;
  }

  ret = test1c();
  if (ret != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "test1c failed\n");
    goto exit;
  }

  ret = test1d();
  if (ret != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "test1d failed\n");
    goto exit;
  }

  ret = test2a();
  if (ret != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "test2a failed\n");
    goto exit;
  }

  ret = test2b();
  if (ret != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "test2b failed\n");
    goto exit;
  }

  ret = test2c();
  if (ret != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "test2c failed\n");
    goto exit;
  }

  ret = test2d();
  if (ret != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "test2d failed\n");
    goto exit;
  }

  ret = test3a();
  if (ret != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "test3a failed\n");
    goto exit;
  }

  ret = test4a();
  if (ret != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "test4a failed\n");
    goto exit;
  }

  ret = test4b();
  if (ret != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "test4b failed\n");
    goto exit;
  }

  ret = 0;
  goto exit;
exit: { return ret; }
}


static int test1a() {
  int ret = 1;

  atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_DEBUG, "test1a Starting...\n");

  atclient_atkey atkey;
  atclient_atkey_init(&atkey);

  char *string = NULL;

  const char *expected = TEST_ATKEY_TO_STRING_1A;
  const size_t expectedlen = strlen(expected);

  atclient_atkey_metadata_set_iscached(&(atkey.metadata), true);
  atclient_atkey_metadata_set_ispublic(&(atkey.metadata), true);

  if ((ret = atclient_atkey_set_key(&atkey, "publickey")) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atclient_atkey_set_key failed\n");
    goto exit;
  }

  if ((ret = atclient_atkey_set_sharedby(&atkey, "@bob")) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atclient_atkey_set_sharedby failed\n");
    goto exit;
  }

  if ((ret = atclient_atkey_to_string(&atkey, &string)) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atclient_atkey_to_string failed\n");
    goto exit;
  }

  if ((ret = strcmp(string, expected)) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "expected: \"%s\", actual: \"%s\"\n", expected, string);
    ret = 1;
    goto exit;
  }

  ret = 0;
exit: {
  atclient_atkey_free(&atkey);
  free(string);
  atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_DEBUG, "test1a Ended:%d\n", ret);
  return ret;
}
}

static int test1b() {
  int ret = 1;

  atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_DEBUG, "test1b Starting...\n");

  atclient_atkey atkey;
  atclient_atkey_init(&atkey);

  char *string = NULL;

  const char *expected = TEST_ATKEY_TO_STRING_1B; // "public:publickey@alice"
  const size_t expectedlen = strlen(expected);

  atclient_atkey_metadata_set_ispublic(&(atkey.metadata), true);

  if ((ret = atclient_atkey_set_key(&atkey, "publickey")) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atclient_atkey_set_key failed\n");
    goto exit;
  }

  if ((ret = atclient_atkey_set_sharedby(&atkey, "@alice")) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atclient_atkey_set_sharedby failed\n");
    goto exit;
  }

  if ((ret = atclient_atkey_to_string(&atkey, &string)) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atclient_atkey_to_string failed\n");
    goto exit;
  }

  if ((ret = strcmp(string, expected)) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "expected: \"%s\", actual: \"%s\"\n", expected, string);
    goto exit;
  }

  ret = 0;
  goto exit;
exit: {
  free(string);
  atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_DEBUG, "test1b Ended:%d\n", ret);
  return ret;
}
}

static int test1c() {
  int ret = 1;

  atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_DEBUG, "test1c Starting...\n");

  atclient_atkey atkey;
  atclient_atkey_init(&atkey);

  char *string = NULL;

  const char *expected = TEST_ATKEY_TO_STRING_1C; // "public:name.wavi@jeremy"
  const size_t expectedlen = strlen(expected);

  atclient_atkey_metadata_set_ispublic(&(atkey.metadata), true);

  if ((ret = atclient_atkey_set_key(&atkey, "name")) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atclient_atkey_set_key failed\n");
    goto exit;
  }

  if ((ret = atclient_atkey_set_sharedby(&atkey, "@jeremy")) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atclient_atkey_set_sharedby failed\n");
    goto exit;
  }

  if ((ret = atclient_atkey_set_namespacestr(&(atkey), "wavi")) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atclient_atkey_set_namespacestr failed\n");
    goto exit;
  }

  if ((ret = atclient_atkey_to_string(&atkey, &string)) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atclient_atkey_to_string failed\n");
    goto exit;
  }

  if ((ret = strcmp(string, expected)) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "expected: \"%s\", actual: \"%s\"\n", expected, string);
    goto exit;
  }

  ret = 0;
  goto exit;
exit: {
  free(string);
  atclient_atkey_free(&atkey);
  atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_DEBUG, "test1c Ended:%d\n", ret);
  return ret;
}
}

static int test1d() {
  int ret = 1;

  atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_DEBUG, "test1d Starting...\n");

  atclient_atkey atkey;
  atclient_atkey_init(&atkey);

  char *string = NULL;

  const char *expected = TEST_ATKEY_TO_STRING_1D; // "cached:public:name.wavi@jeremy"
  const size_t expectedlen = strlen(expected);

  atclient_atkey_metadata_set_iscached(&(atkey.metadata), true);
  atclient_atkey_metadata_set_ispublic(&(atkey.metadata), true);

  if ((ret = atclient_atkey_set_key(&atkey, "name")) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atclient_atkey_set_key failed\n");
    goto exit;
  }

  if ((ret = atclient_atkey_set_namespacestr(&(atkey), "wavi")) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atclient_atkey_set_namespacestr failed\n");
    goto exit;
  }

  if ((ret = atclient_atkey_set_sharedby(&atkey, "@jeremy")) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atclient_atkey_set_sharedby failed\n");
    goto exit;
  }

  if ((ret = atclient_atkey_to_string(&atkey, &string)) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atclient_atkey_to_string failed\n");
    goto exit;
  }

  if ((ret = strcmp(string, expected)) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "expected: \"%s\", actual: \"%s\"\n", expected, string);
    goto exit;
  }

  ret = 0;
exit: {
  free(string);
  atclient_atkey_free(&atkey);
  atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_DEBUG, "test1d Ended:%d\n", ret);
  return ret;
}
}

static int test2a() {
  int ret = 1;

  atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_DEBUG, "test2a Starting...\n");

  atclient_atkey atkey;
  atclient_atkey_init(&atkey);

  char *string = NULL;

  const char *expected = TEST_ATKEY_TO_STRING_2A; // "@alice:name.wavi@bob"

  if ((ret = atclient_atkey_set_key(&atkey, "name")) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atclient_atkey_set_key failed\n");
    goto exit;
  }

  if ((ret = atclient_atkey_set_sharedby(&atkey, "@bob")) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atclient_atkey_set_sharedby failed\n");
    goto exit;
  }

  if ((ret = atclient_atkey_set_namespacestr(&atkey, "wavi")) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atclient_atkey_set_namespacestr failed\n");
    goto exit;
  }

  if ((ret = atclient_atkey_set_sharedwith(&atkey, "@alice")) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atclient_atkey_set_sharedwith failed\n");
    goto exit;
  }

  if ((ret = atclient_atkey_to_string(&atkey, &string)) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atclient_atkey_to_string failed\n");
    goto exit;
  }

  if ((ret = strcmp(string, expected)) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "expected: \"%s\", actual: \"%s\"\n", expected, string);
    goto exit;
  }

  ret = 0;
exit: {
  free(string);
  atclient_atkey_free(&atkey);
  atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_DEBUG, "test2a Ended:%d\n", ret);
  return ret;
}
}

static int test2b() {
  int ret = 1;

  atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_DEBUG, "test2b Starting...\n");

  atclient_atkey atkey;
  atclient_atkey_init(&atkey);

  char *string = NULL;

  const char *expected = TEST_ATKEY_TO_STRING_2B; // "cached:@bob:name@alice"

  atclient_atkey_metadata_set_iscached(&(atkey.metadata), true);

  if ((ret = atclient_atkey_set_sharedwith(&atkey, "@bob")) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atclient_atkey_set_sharedwith failed\n");
    goto exit;
  }

  if ((ret = atclient_atkey_set_key(&atkey, "name")) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atclient_atkey_set_key failed\n");
    goto exit;
  }

  if ((ret = atclient_atkey_set_sharedby(&atkey, "@alice")) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atclient_atkey_set_sharedby failed\n");
    goto exit;
  }

  if ((ret = atclient_atkey_to_string(&atkey, &string)) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atclient_atkey_to_string failed\n");
    goto exit;
  }

  if ((ret = strcmp(string, expected)) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "expected: \"%s\", actual: \"%s\"\n", expected, string);
    goto exit;
  }

  ret = 0;
  goto exit;
exit: {
  free(string);
  atclient_atkey_free(&atkey);
  atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_DEBUG, "test2b Ended:%d\n", ret);
  return ret;
}
}

static int test2c() {
  int ret = 1;

  atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_DEBUG, "test2c Starting...\n");

  atclient_atkey atkey;
  atclient_atkey_init(&atkey);

  char *string = NULL;

  const char *expected = TEST_ATKEY_TO_STRING_2C; // "@bob:name@alice"

  if ((ret = atclient_atkey_set_sharedby(&atkey, "@alice")) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atclient_atkey_set_sharedby failed\n");
    goto exit;
  }

  if ((ret = atclient_atkey_set_key(&atkey, "name")) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atclient_atkey_set_key failed\n");
    goto exit;
  }

  if ((ret = atclient_atkey_set_sharedwith(&atkey, "@bob")) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atclient_atkey_set_sharedwith failed\n");
    goto exit;
  }

  if ((ret = atclient_atkey_to_string(&atkey, &string)) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atclient_atkey_to_string failed\n");
    goto exit;
  }

  // namespace should be empty
  if (atclient_atkey_is_namespacestr_initialized(&atkey) || strlen(atkey.namespacestr) > 0) {
    ret = 1;
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "namespacestr is initialized when it isn't supposed to be\n");
    goto exit;
  }

  if ((ret = strcmp(string, expected)) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "expected: \"%s\", actual: \"%s\"\n", expected, string);
    goto exit;
  }

  ret = 0;
  goto exit;
exit: {
  free(string);
  atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_DEBUG, "test2c Ended:%d\n", ret);
  return ret;
}
}

static int test2d() {
  int ret = 1;

  atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_DEBUG, "test2d Starting...\n");

  atclient_atkey atkey;
  atclient_atkey_init(&atkey);

  char *string = NULL;

  const char *expected = TEST_ATKEY_TO_STRING_2D; // "cached:@bob:name.wavi@alice"

  atclient_atkey_metadata_set_iscached(&(atkey.metadata), true);

  if ((ret = atclient_atkey_set_sharedwith(&atkey, "@bob")) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atclient_atkey_set_sharedwith failed\n");
    goto exit;
  }

  if ((ret = atclient_atkey_set_key(&atkey, "name")) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atclient_atkey_set_key failed\n");
    goto exit;
  }

  if ((ret = atclient_atkey_set_sharedby(&atkey, "@alice")) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atclient_atkey_set_sharedby failed\n");
    goto exit;
  }

  if ((ret = atclient_atkey_set_namespacestr(&atkey, "wavi")) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atclient_atkey_set_namespacestr failed\n");
    goto exit;
  }

  if ((ret = atclient_atkey_to_string(&atkey, &string)) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atclient_atkey_to_string failed\n");
    goto exit;
  }

  if ((ret = strcmp(string, expected)) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "expected: \"%s\", actual: \"%s\"\n", expected, string);
    goto exit;
  }

  ret = 0;
exit: {
  free(string);
  atclient_atkey_free(&atkey);
  atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_DEBUG, "test2d Ended:%d\n", ret);
  return ret;
}
}

static int test3a() {
  int ret = 1;

  atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_DEBUG, "test3a Starting...\n");

  atclient_atkey atkey;
  atclient_atkey_init(&atkey);

  char *string = NULL;

  const char *expected = TEST_ATKEY_TO_STRING_3A; // "_lastnotificationid@alice123_4😘"

  if ((ret = atclient_atkey_set_key(&atkey, "_lastnotificationid")) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atclient_atkey_set_key failed\n");
    goto exit;
  }

  if ((ret = atclient_atkey_set_sharedby(&atkey, "@alice123_4😘")) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atclient_atkey_set_sharedby failed\n");
    goto exit;
  }

  if (atclient_atkey_is_sharedwith_initialized(&atkey) || strlen(atkey.sharedwith) > 0) {
    ret = 1;
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "sharedwith is initialized when it isn't supposed to be\n");
    goto exit;
  }

  if (atclient_atkey_is_namespacestr_initialized(&atkey) || strlen(atkey.namespacestr) > 0) {
    ret = 1;
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "namespacestr is initialized when it isn't supposed to be\n");
    goto exit;
  }

  if ((ret = atclient_atkey_to_string(&atkey, &string)) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atclient_atkey_to_string failed\n");
    goto exit;
  }

  if ((ret = strcmp(string, expected)) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "expected: \"%s\", actual: \"%s\"\n", expected, string);
    ret = 1;
    goto exit;
  }

  ret = 0;
exit: {
  free(string);
  atclient_atkey_free(&atkey);
  atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_DEBUG, "test3a Ended:%d\n", ret);
  return ret;
}
}

static int test4a() {
  int ret = 1;

  atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_DEBUG, "test4a Starting...\n");

  atclient_atkey atkey;
  atclient_atkey_init(&atkey);

  char *string = NULL;

  const char *expected = TEST_ATKEY_TO_STRING_4A; // "name@alice"

  if ((ret = atclient_atkey_set_key(&atkey, "name")) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atclient_atkey_set_key failed\n");
    goto exit;
  }

  if ((ret = atclient_atkey_set_sharedby(&atkey, "@alice")) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atclient_atkey_set_sharedby failed\n");
    goto exit;
  }

  if ((ret = atclient_atkey_to_string(&atkey, &string)) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atclient_atkey_to_string failed\n");
    goto exit;
  }

  if (atclient_atkey_is_sharedwith_initialized(&atkey) || strlen(atkey.sharedwith) > 0) {
    ret = 1;
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "sharedwith is initialized when it isn't supposed to be\n");
    goto exit;
  }

  if (atclient_atkey_is_namespacestr_initialized(&atkey) || strlen(atkey.namespacestr) > 0) {
    ret = 1;
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "namespacestr is initialized when it isn't supposed to be\n");
    goto exit;
  }

  if ((ret = strcmp(string, expected)) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "expected: \"%s\", actual: \"%s\"\n", expected, string);
    ret = 1;
    goto exit;
  }

  ret = 0;
  goto exit;
exit: {
  free(string);
  atclient_atkey_free(&atkey);
  atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_DEBUG, "test4a Ended:%d\n", ret);
  return ret;
}
}

static int test4b() {
  int ret = 1;

  atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_DEBUG, "test4b Starting...\n");

  atclient_atkey atkey;
  atclient_atkey_init(&atkey);

  const char *expected = TEST_ATKEY_TO_STRING_4B; // "name.wavi@jeremy_0"

  char *atkeystr = NULL;

  if ((ret = atclient_atkey_set_key(&atkey, "name")) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atclient_atkey_set_key failed\n");
    goto exit;
  }

  if ((ret = atclient_atkey_set_sharedby(&atkey, "@jeremy_0")) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atclient_atkey_set_sharedby failed\n");
    goto exit;
  }

  if ((ret = atclient_atkey_set_namespacestr(&atkey, "wavi")) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atclient_atkey_set_namespacestr failed\n");
    goto exit;
  }

  if ((ret = atclient_atkey_to_string(&atkey, &atkeystr)) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atclient_atkey_to_string failed\n");
    goto exit;
  }

  if ((ret = strcmp(atkeystr, expected)) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "expected: \"%s\", actual: \"%s\"\n", expected, atkeystr);
    goto exit;
  }

  ret = 0;
exit: {
  atclient_atkey_free(&atkey);
  free(atkeystr);
  atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_DEBUG, "test4b Ended:%d\n", ret);
  return ret;
}
}

