#include "functional_tests/config.h"
#include <atclient/atclient.h>
#include <atlogger/atlogger.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define TAG "test_atclient_selfkey"

#define ATKEY_NAME "test_atclient_selfkey"
#define ATKEY_NAMESPACE "functional_tests"
#define ATKEY_SHAREDBY FIRST_ATSIGN
#define ATKEY_VALUE "my self value"
#define ATKEY_TTL 1000 * 60 * 5 // 5 minutes
#define ATKEY_ISENCRYPTED true
#define ATKEY_ISBINARY false

static int pkam_auth(atclient *atclient, const char *atsign);
static int should_not_exist(atclient *atclient, const char *key, const char *sharedby, const char *namespace);
static int delete(atclient *atclient, const char *key, const char *sharedby, const char *namespace);

static int test_1_should_not_exist(atclient *atclient);
static int test_2_put(atclient *atclient);
static int test_3_get(atclient *atclient);
static int test_4_delete(atclient *atclient);
static int test_5_should_not_exist(atclient *atclient);
static int test_6_put_with_metadata(atclient *atclient);
static int test_7_get_with_metadata(atclient *atclient);
static int test_8_delete(atclient *atclient);
static int test_9_should_not_exist(atclient *atclient);

int main() {
  int ret = 1;

  atlogger_set_logging_level(ATLOGGER_LOGGING_LEVEL_DEBUG);

  atclient atclient;
  atclient_init(&atclient);

  if ((ret = pkam_auth(&atclient, ATKEY_SHAREDBY)) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "Failed to authenticate with PKAM");
    goto exit;
  }

  if ((ret = test_1_should_not_exist(&atclient)) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "Failed test_1_should_not_exist");
    goto exit;
  }

  if ((ret = test_2_put(&atclient)) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "Failed test_2_put");
    goto exit;
  }

  if ((ret = test_3_get(&atclient)) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "Failed test_3_get");
    goto exit;
  }

  if ((ret = test_4_delete(&atclient)) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "Failed test_4_delete");
    goto exit;
  }

  if ((ret = test_5_should_not_exist(&atclient)) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "Failed test_5_should_not_exist");
    goto exit;
  }

  if ((ret = test_6_put_with_metadata(&atclient)) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "Failed test_6_put_with_metadata");
    goto exit;
  }

  if ((ret = test_7_get_with_metadata(&atclient)) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "Failed test_7_get_with_metadata");
    goto exit;
  }

  if ((ret = test_8_delete(&atclient)) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "Failed test_8_delete");
    goto exit;
  }

  if ((ret = test_9_should_not_exist(&atclient)) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "Failed test_9_should_not_exist");
    goto exit;
  }

  ret = 0;

  goto exit;
exit: { return ret; }
}

static int pkam_auth(atclient *atclient, const char *atsign) {
  int ret = 1;

  atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_INFO, "pkam_auth Begin\n");

  const size_t atkeysfilepathsize = 1024;
  char atkeysfilepath[atkeysfilepathsize];
  memset(atkeysfilepath, 0, sizeof(char) * atkeysfilepathsize);
  size_t atkeysfilepathlen = 0;

  atclient_connection root_connection;
  atclient_connection_init(&root_connection);

  atclient_atkeys atkeys;
  atclient_atkeys_init(&atkeys);

  atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_INFO, "atsign: \"%s\"\n", atsign);

  if ((ret = get_atkeys_path(atsign, strlen(atsign), atkeysfilepath, atkeysfilepathsize, &atkeysfilepathlen)) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "get_atkeys_path: %d\n", ret);
    goto exit;
  }
  atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_INFO, "atkeysfilepath: \"%s\"\n", atkeysfilepath);

  if ((ret = atclient_atkeys_populate_from_path(&atkeys, atkeysfilepath)) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atclient_atkeys_populate_from_path: %d\n", ret);
    goto exit;
  }
  atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_INFO, "atkeys populated\n");

  if ((ret = atclient_connection_connect(&root_connection, ROOT_HOST, ROOT_PORT)) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atclient_connection_connect: %d\n", ret);
    goto exit;
  }
  atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_INFO, "root connection established\n");

  if ((ret = atclient_pkam_authenticate(atclient, &root_connection, &atkeys, atsign)) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atclient_pkam_authenticate: %d\n", ret);
    goto exit;
  }
  atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_INFO, "pkam authenticated\n");

  goto exit;

exit: {
  atclient_connection_free(&root_connection);
  atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_INFO, "pkam_auth End (%d)\n", ret);
  return ret;
}
}

static int should_not_exist(atclient *atclient, const char *key, const char *sharedby, const char *namespace) {
  int ret = 1;

  atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_INFO, "should_not_exist Begin\n");

  atclient_atkey atkey;
  atclient_atkey_init(&atkey);

  const short atkeystrsize = 128;
  char atkeystr[atkeystrsize];
  memset(atkeystr, 0, sizeof(char) * atkeystrsize);
  size_t atkeystrlen = 0;

  if (namespace == NULL) {
    snprintf(atkeystr, atkeystrsize, "%s%s", key, sharedby);
  } else {
    snprintf(atkeystr, atkeystrsize, "%s.%s%s", key, namespace, sharedby);
  }

  if ((ret = atclient_atkey_from_string(&atkey, atkeystr, strlen(atkeystr))) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atclient_atkey_from_string: %d\n", ret);
    goto exit;
  }

  if ((ret = atclient_get_selfkey(atclient, &atkey, key, sharedby, namespace)) == 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_INFO, "atclient_get_selfkey: %d\n", ret);
    ret = 1;
    goto exit;
  }

  ret = 0;
  goto exit;
exit: {
  atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_INFO, "should_not_exist End (%d)\n", ret);
  return ret;
}
}

static int delete(atclient *atclient, const char *key, const char *sharedby, const char *namespace) {
  int ret = 1;

  atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_INFO, "delete Begin\n");

  atclient_atkey atkey;
  atclient_atkey_init(&atkey);

  if ((ret = atclient_atkey_create_selfkey(&atkey, ATKEY_NAME, strlen(ATKEY_NAME), ATKEY_SHAREDBY,
                                           strlen(ATKEY_SHAREDBY), ATKEY_NAMESPACE, strlen(ATKEY_NAMESPACE))) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atclient_atkey_create_selfkey: %d\n", ret);
    goto exit;
  }

  if ((ret = atclient_delete(atclient, &atkey)) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atclient_delete: %d\n", ret);
    goto exit;
  }

  goto exit;
exit: {
  atclient_atkey_free(&atkey);
  atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_INFO, "delete End (%d)\n", ret);
  return ret;
}
}

static int test_1_should_not_exist(atclient *atclient) {
  int ret = 1;

  atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_INFO, "test_1_should_not_exist Begin\n");

  if ((ret = should_not_exist(atclient, ATKEY_NAME, ATKEY_SHAREDBY, ATKEY_NAMESPACE)) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "should_not_exist: %d\n", ret);
    goto exit;
  }

  goto exit;
exit: {
  atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_INFO, "test_1_should_not_exist End (%d)\n", ret);
  return ret;
}
}

static int test_2_put(atclient *atclient) {
  int ret = 1;

  atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_INFO, "test_2_put Begin\n");

  atclient_atkey atkey;
  atclient_atkey_init(&atkey);

  if ((ret = atclient_atkey_create_selfkey(&atkey, ATKEY_NAME, strlen(ATKEY_NAME), ATKEY_SHAREDBY,
                                           strlen(ATKEY_SHAREDBY), ATKEY_NAMESPACE, strlen(ATKEY_NAMESPACE))) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atclient_atkey_create_selfkey: %d\n", ret);
    goto exit;
  }

  if ((ret = atclient_put(atclient, &atkey, ATKEY_VALUE, strlen(ATKEY_VALUE), NULL)) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atclient_put: %d\n", ret);
    goto exit;
  }

  goto exit;
exit: {
  atclient_atkey_free(&atkey);
  atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_INFO, "test_2_put End (%d)\n", ret);
  return ret;
}
}

static int test_3_get(atclient *atclient) {
  int ret = 1;

  atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_INFO, "test_3_get Begin\n");

  atclient_atkey atkey;
  atclient_atkey_init(&atkey);

  const size_t valuesize = 512;
  char value[valuesize];
  memset(value, 0, sizeof(char) * valuesize);
  size_t valuelen = 0;

  if ((ret = atclient_atkey_create_selfkey(&atkey, ATKEY_NAME, strlen(ATKEY_NAME), ATKEY_SHAREDBY,
                                           strlen(ATKEY_SHAREDBY), ATKEY_NAMESPACE, strlen(ATKEY_NAMESPACE))) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atclient_get: %d\n", ret);
    goto exit;
  }

  if ((ret = atclient_get_selfkey(atclient, &atkey, value, valuesize, &valuelen)) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atclient_get: %d\n", ret);
    goto exit;
  }
  atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_INFO, "value: \"%.*s\"\n", (int) valuelen, value);

  if (memcmp(value, ATKEY_VALUE, strlen(ATKEY_VALUE)) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atkey.value: \"%s\" != \"%s\"\n", value, ATKEY_VALUE);
    ret = 1;
    goto exit;
  }

  ret = 0;
  goto exit;
exit: {
  atclient_atkey_free(&atkey);
  atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_INFO, "test_3_get End (%d)\n", ret);
  return ret;
}
}

static int test_4_delete(atclient *atclient) {
  int ret = 1;

  atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_INFO, "test_4_delete Begin\n");

  if ((ret = delete (atclient, ATKEY_NAME, ATKEY_SHAREDBY, ATKEY_NAMESPACE)) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "delete: %d\n", ret);
    goto exit;
  }

  goto exit;
exit: {
  atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_INFO, "test_4_delete End (%d)\n", ret);
  return ret;
}
}

static int test_5_should_not_exist(atclient *atclient) {
  int ret = 1;

  atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_INFO, "test_5_should_not_exist Begin\n");

  if ((ret = should_not_exist(atclient, ATKEY_NAME, ATKEY_SHAREDBY, ATKEY_NAMESPACE)) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "should_not_exist: %d\n", ret);
    goto exit;
  }

  goto exit;
exit: {
  atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_INFO, "test_5_should_not_exist End (%d)\n", ret);
  return ret;
}
}

static int test_6_put_with_metadata(atclient *atclient) {
  int ret = 1;

  atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_INFO, "test_6_put_with_metadata Begin\n");

  atclient_atkey atkey;
  atclient_atkey_init(&atkey);

  if ((ret = atclient_atkey_create_selfkey(&atkey, ATKEY_NAME, strlen(ATKEY_NAME), ATKEY_SHAREDBY,
                                           strlen(ATKEY_SHAREDBY), ATKEY_NAMESPACE, strlen(ATKEY_NAMESPACE))) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atclient_atkey_create_selfkey: %d\n", ret);
    goto exit;
  }

  atclient_atkey_metadata_set_ttl(&(atkey.metadata), ATKEY_TTL);
  atclient_atkey_metadata_set_isencrypted(&(atkey.metadata), ATKEY_ISENCRYPTED);
  atclient_atkey_metadata_set_isbinary(&(atkey.metadata), ATKEY_ISBINARY);

  if ((ret = atclient_put(atclient, &atkey, ATKEY_VALUE, strlen(ATKEY_VALUE), NULL)) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atclient_put: %d\n", ret);
    goto exit;
  }

  goto exit;
exit: {
  atclient_atkey_free(&atkey);
  atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_INFO, "test_6_put_with_metadata End (%d)\n", ret);
  return ret;
}
}

static int test_7_get_with_metadata(atclient *atclient) {
  int ret = 1;

  atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_INFO, "test_7_get_with_metadata Begin\n");

  atclient_atkey atkey;
  atclient_atkey_init(&atkey);

  const size_t valuesize = 512;
  char value[valuesize];
  memset(value, 0, sizeof(char) * valuesize);
  size_t valuelen = 0;

  if ((ret = atclient_atkey_create_selfkey(&atkey, ATKEY_NAME, strlen(ATKEY_NAME), ATKEY_SHAREDBY,
                                           strlen(ATKEY_SHAREDBY), ATKEY_NAMESPACE, strlen(ATKEY_NAMESPACE))) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atclient_get: %d\n", ret);
    goto exit;
  }

  if ((ret = atclient_get_selfkey(atclient, &atkey, value, valuesize, &valuelen)) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atclient_get: %d\n", ret);
    goto exit;
  }

  if (memcmp(value, ATKEY_VALUE, strlen(ATKEY_VALUE)) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atkey.value: \"%s\" != \"%s\"\n", value, ATKEY_VALUE);
    ret = 1;
    goto exit;
  }

  if (atkey.metadata.ttl != ATKEY_TTL) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atkey.metadata.ttl: %d != %d\n", atkey.metadata.ttl, ATKEY_TTL);
    ret = 1;
    goto exit;
  }

  if (atkey.metadata.isencrypted != ATKEY_ISENCRYPTED) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atkey.metadata.isencrypted: %d != %d\n",
                 atkey.metadata.isencrypted, true);
    ret = 1;
    goto exit;
  }

  if (atkey.metadata.isbinary != ATKEY_ISBINARY) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atkey.metadata.isbinary: %d != %d\n", atkey.metadata.isbinary,
                 false);
    ret = 1;
    goto exit;
  }

  ret = 0;
  goto exit;
exit: {
  atclient_atkey_free(&atkey);
  atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_INFO, "test_7_get_with_metadata End (%d)\n", ret);
  return ret;
}
}

static int test_8_delete(atclient *atclient) {
  int ret = 1;

  atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_INFO, "test_8_delete Begin\n");

  if ((ret = delete (atclient, ATKEY_NAME, ATKEY_SHAREDBY, ATKEY_NAMESPACE)) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "delete: %d\n", ret);
    goto exit;
  }

  goto exit;
exit: {
  atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_INFO, "test_8_delete End (%d)\n", ret);
  return ret;
}
}

static int test_9_should_not_exist(atclient *atclient) {
  int ret = 1;

  atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_INFO, "test_9_should_not_exist Begin\n");

  if ((ret = should_not_exist(atclient, ATKEY_NAME, ATKEY_SHAREDBY, ATKEY_NAMESPACE)) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "should_not_exist: %d\n", ret);
    goto exit;
  }

  goto exit;
exit: {
  atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_INFO, "test_9_should_not_exist End (%d)\n", ret);
  return ret;
}
}
