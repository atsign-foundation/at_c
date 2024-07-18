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

static int test1a_cached_publickey_without_namespace();
static int test1b_publickey_without_namespace();
static int test1c_publickey_with_namespace();
static int test1d_cached_publickey_with_namespace();
static int test2a_sharedkey_with_namespace();
static int test2b_cached_sharedkey_without_namespace();
static int test2c_sharedkey_without_namespace();
static int test2d_cached_sharedkey_with_namespace();
static int test3a_privatehiddenkey();
static int test4a_selfkey_without_namespace();
static int test4b_selfkey_with_namespace();

int main() {
  int ret = 1;

  atlogger_set_logging_level(ATLOGGER_LOGGING_LEVEL_DEBUG);

  ret = test1a_cached_publickey_without_namespace();
  if (ret != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "test1a_cached_publickey_without_namespace failed\n");
    goto exit;
  }

  ret = test1b_publickey_without_namespace();
  if (ret != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "test1b_publickey_without_namespace failed\n");
    goto exit;
  }

  ret = test1c_publickey_with_namespace();
  if (ret != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "test1c_publickey_with_namespace failed\n");
    goto exit;
  }

  ret = test1d_cached_publickey_with_namespace();
  if (ret != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "test1d_cached_publickey_with_namespace failed\n");
    goto exit;
  }

  ret = test2a_sharedkey_with_namespace();
  if (ret != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "test2a_sharedkey_with_namespace failed\n");
    goto exit;
  }

  ret = test2b_cached_sharedkey_without_namespace();
  if (ret != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "test2b_cached_sharedkey_without_namespace failed\n");
    goto exit;
  }

  ret = test2c_sharedkey_without_namespace();
  if (ret != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "test2c_sharedkey_without_namespace failed\n");
    goto exit;
  }

  ret = test2d_cached_sharedkey_with_namespace();
  if (ret != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "test2d_cached_sharedkey_with_namespace failed\n");
    goto exit;
  }

  ret = test3a_privatehiddenkey();
  if (ret != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "test3a_privatehiddenkey failed\n");
    goto exit;
  }

  ret = test4a_selfkey_without_namespace();
  if (ret != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "test4a_selfkey_without_namespace failed\n");
    goto exit;
  }

  ret = test4b_selfkey_with_namespace();
  if (ret != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "test4b_selfkey_with_namespace failed\n");
    goto exit;
  }

  ret = 0;
  goto exit;
exit: { return ret; }
}

static int test1a_cached_publickey_without_namespace() {
  int ret = 1;

  atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_DEBUG, "test1a_cached_publickey_without_namespace Starting...\n");

  atclient_atkey atkey;
  atclient_atkey_init(&atkey);

  char *string = NULL;

  const char *expected = TEST_ATKEY_TO_STRING_1A;

  if((ret = atclient_atkey_metadata_set_iscached(&(atkey.metadata), true)) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atclient_atkey_metadata_set_iscached failed\n");
    goto exit;
  }

  if((ret = atclient_atkey_metadata_set_ispublic(&(atkey.metadata), true)) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atclient_atkey_metadata_set_ispublic failed\n");
    goto exit;
  }

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
  atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_DEBUG, "test1a_cached_publickey_without_namespace Ended:%d\n", ret);
  return ret;
}
}

static int test1b_publickey_without_namespace() {
  int ret = 1;

  atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_DEBUG, "test1b_publickey_without_namespace Starting...\n");

  atclient_atkey atkey;
  atclient_atkey_init(&atkey);

  char *string = NULL;

  const char *expected = TEST_ATKEY_TO_STRING_1B; // "public:publickey@alice"

  if((ret = atclient_atkey_metadata_set_ispublic(&(atkey.metadata), true)) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atclient_atkey_metadata_set_ispublic failed\n");
    goto exit;
  }

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
  atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_DEBUG, "test1b_publickey_without_namespace Ended:%d\n", ret);
  return ret;
}
}

static int test1c_publickey_with_namespace() {
  int ret = 1;

  atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_DEBUG, "test1c_publickey_with_namespace Starting...\n");

  atclient_atkey atkey;
  atclient_atkey_init(&atkey);

  char *string = NULL;

  const char *expected = TEST_ATKEY_TO_STRING_1C; // "public:name.wavi@jeremy"

  if ((ret = atclient_atkey_metadata_set_ispublic(&(atkey.metadata), true)) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atclient_atkey_metadata_set_ispublic failed\n");
    goto exit;
  }

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
exit: {
  free(string);
  atclient_atkey_free(&atkey);
  atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_DEBUG, "test1c_publickey_with_namespace Ended:%d\n", ret);
  return ret;
}
}

static int test1d_cached_publickey_with_namespace() {
  int ret = 1;

  atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_DEBUG, "test1d_cached_publickey_with_namespace Starting...\n");

  atclient_atkey atkey;
  atclient_atkey_init(&atkey);

  char *string = NULL;

  const char *expected = TEST_ATKEY_TO_STRING_1D; // "cached:public:name.wavi@jeremy"
  const size_t expectedlen = strlen(expected);

  if((ret = atclient_atkey_metadata_set_iscached(&(atkey.metadata), true)) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atclient_atkey_metadata_set_iscached failed\n");
    goto exit;
  }

  if((ret = atclient_atkey_metadata_set_ispublic(&(atkey.metadata), true)) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atclient_atkey_metadata_set_ispublic failed\n");
    goto exit;
  }

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
  atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_DEBUG, "test1d_cached_publickey_with_namespace Ended:%d\n", ret);
  return ret;
}
}

static int test2a_sharedkey_with_namespace() {
  int ret = 1;

  atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_DEBUG, "test2a_sharedkey_with_namespace Starting...\n");

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
  atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_DEBUG, "test2a_sharedkey_with_namespace Ended:%d\n", ret);
  return ret;
}
}

static int test2b_cached_sharedkey_without_namespace() {
  int ret = 1;

  atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_DEBUG, "test2b_cached_sharedkey_without_namespace Starting...\n");

  atclient_atkey atkey;
  atclient_atkey_init(&atkey);

  char *string = NULL;

  const char *expected = TEST_ATKEY_TO_STRING_2B; // "cached:@bob:name@alice"

  if((ret = atclient_atkey_metadata_set_iscached(&(atkey.metadata), true)) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atclient_atkey_metadata_set_iscached failed\n");
    goto exit;
  }

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
  atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_DEBUG, "test2b_cached_sharedkey_without_namespace Ended:%d\n", ret);
  return ret;
}
}

static int test2c_sharedkey_without_namespace() {
  int ret = 1;

  atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_DEBUG, "test2c_sharedkey_without_namespace Starting...\n");

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

  if (atclient_atkey_is_namespacestr_initialized(&atkey)) {
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
  atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_DEBUG, "test2c_sharedkey_without_namespace Ended:%d\n", ret);
  return ret;
}
}

static int test2d_cached_sharedkey_with_namespace() {
  int ret = 1;

  atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_DEBUG, "test2d_cached_sharedkey_with_namespace Starting...\n");

  atclient_atkey atkey;
  atclient_atkey_init(&atkey);

  char *string = NULL;

  const char *expected = TEST_ATKEY_TO_STRING_2D; // "cached:@bob:name.wavi@alice"

  if((ret = atclient_atkey_metadata_set_iscached(&(atkey.metadata), true)) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atclient_atkey_metadata_set_iscached failed\n");
    goto exit;
  }

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
  atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_DEBUG, "test2d_cached_sharedkey_with_namespace Ended:%d\n", ret);
  return ret;
}
}

static int test3a_privatehiddenkey() {
  int ret = 1;

  atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_DEBUG, "test3a_privatehiddenkey Starting...\n");

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

  if (atclient_atkey_is_sharedwith_initialized(&atkey)) {
    ret = 1;
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "sharedwith is initialized when it isn't supposed to be\n");
    goto exit;
  }

  if (atclient_atkey_is_namespacestr_initialized(&atkey)) {
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
  atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_DEBUG, "test3a_privatehiddenkey Ended:%d\n", ret);
  return ret;
}
}

static int test4a_selfkey_without_namespace() {
  int ret = 1;

  atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_DEBUG, "test4a_selfkey_without_namespace Starting...\n");

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

  if (atclient_atkey_is_sharedwith_initialized(&atkey)) {
    ret = 1;
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "sharedwith is initialized when it isn't supposed to be\n");
    goto exit;
  }

  if (atclient_atkey_is_namespacestr_initialized(&atkey)) {
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
  atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_DEBUG, "test4a_selfkey_without_namespace Ended:%d\n", ret);
  return ret;
}
}

static int test4b_selfkey_with_namespace() {
  int ret = 1;

  atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_DEBUG, "test4b_selfkey_with_namespace Starting...\n");

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
  atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_DEBUG, "test4b_selfkey_with_namespace Ended:%d\n", ret);
  return ret;
}
}
