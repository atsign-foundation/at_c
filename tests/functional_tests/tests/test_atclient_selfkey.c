#include "functional_tests/config.h"
#include "functional_tests/helpers.h"
#include <atclient/atclient.h>
#include <atclient/stringutils.h>
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

static int test_1_should_not_exist(atclient *atclient);
static int test_2_put(atclient *atclient);
static int test_3_get(atclient *atclient);
static int test_4_delete(atclient *atclient);
static int test_5_should_not_exist(atclient *atclient);
static int test_6_put_with_metadata(atclient *atclient);
static int test_7_get_with_metadata(atclient *atclient);
static int test_8_delete(atclient *atclient);
static int test_9_should_not_exist(atclient *atclient);
static int tear_down(atclient *atclient);

int main() {
  int ret = 1;

  atlogger_set_logging_level(ATLOGGER_LOGGING_LEVEL_DEBUG);

  atclient atclient;
  atclient_init(&atclient);

  if ((ret = functional_tests_pkam_auth(&atclient, ATKEY_SHAREDBY)) != 0) {
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
exit: {
  atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_INFO, "tear_down: %d\n", tear_down(&atclient));
  atclient_free(&atclient);
  return ret;
}
}

static int test_1_should_not_exist(atclient *atclient) {
  int ret = 1;

  atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_INFO, "test_1_should_not_exist Begin\n");

  if ((ret = functional_tests_selfkey_exists(atclient, ATKEY_NAME, ATKEY_SHAREDBY, ATKEY_NAMESPACE)) == true) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "functional_tests_selfkey_exists: %d\n", ret);
    ret = 1;
    goto exit;
  }
  atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_INFO, "atkey does not exist, which is expected.\n");
  ret = 0;
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
  atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_INFO, "value: \"%.*s\"\n", (int)valuelen, value);

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

  atclient_atkey atkey;
  atclient_atkey_init(&atkey);

  if ((ret = atclient_atkey_create_selfkey(&atkey, ATKEY_NAME, strlen(ATKEY_NAME), ATKEY_SHAREDBY,
                                           strlen(ATKEY_SHAREDBY), ATKEY_NAMESPACE,
                                           ATKEY_NAMESPACE == NULL ? 0 : strlen(ATKEY_NAMESPACE))) != 0) {
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
  atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_INFO, "test_4_delete End (%d)\n", ret);
  return ret;
}
}

static int test_5_should_not_exist(atclient *atclient) {
  int ret = 1;

  atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_INFO, "test_5_should_not_exist Begin\n");

  if ((ret = functional_tests_selfkey_exists(atclient, ATKEY_NAME, ATKEY_SHAREDBY, ATKEY_NAMESPACE)) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "functional_tests_atkey_should_not_exist: %d\n", ret);
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

  atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_INFO, "test_4_delete Begin\n");

  atclient_atkey atkey;
  atclient_atkey_init(&atkey);

  if ((ret = atclient_atkey_create_selfkey(&atkey, ATKEY_NAME, strlen(ATKEY_NAME), ATKEY_SHAREDBY,
                                           strlen(ATKEY_SHAREDBY), ATKEY_NAMESPACE,
                                           ATKEY_NAMESPACE == NULL ? 0 : strlen(ATKEY_NAMESPACE))) != 0) {
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
  atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_INFO, "test_4_delete End (%d)\n", ret);
  return ret;
}
}

static int test_9_should_not_exist(atclient *atclient) {
  int ret = 1;

  atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_INFO, "test_9_should_not_exist Begin\n");

  if ((ret = functional_tests_selfkey_exists(atclient, ATKEY_NAME, ATKEY_SHAREDBY, ATKEY_NAMESPACE)) != false) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "functional_tests_atkey_should_not_exist: %d\n", ret);
    goto exit;
  }

  goto exit;
exit: {
  atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_INFO, "test_9_should_not_exist End (%d)\n", ret);
  return ret;
}
}

static int tear_down(atclient *atclient) {
  int ret = 1;

  atclient_atkey atkey;
  atclient_atkey_init(&atkey);

  const size_t atkeystrsize = 128;
  char atkeystr[atkeystrsize];
  memset(atkeystr, 0, sizeof(char) * atkeystrsize);
  size_t atkeystrlen = 0;

  const size_t commandsize = 256;
  char command[commandsize];
  memset(command, 0, sizeof(char) * commandsize);
  size_t commandlen = 0;

  const size_t recvsize = 256;
  char recv[recvsize];
  memset(recv, 0, sizeof(char) * recvsize);
  size_t recvlen = 0;

  if (ATKEY_NAMESPACE == NULL) {
    snprintf(atkeystr, atkeystrsize, "%s%s", ATKEY_NAME, ATKEY_SHAREDBY);
  } else {
    snprintf(atkeystr, atkeystrsize, "%s.%s%s", ATKEY_NAME, ATKEY_NAMESPACE, ATKEY_SHAREDBY);
  }

  snprintf(command, commandsize, "delete:%s\r\n", atkeystr);
  commandlen = strlen(command);

  if ((ret = atclient_connection_send(&(atclient->secondary_connection), (unsigned char *)command, commandlen,
                                      (unsigned char *)recv, recvsize, &recvlen)) != 0) {
    ret = 1;
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atclient_connection_send: %d\n", ret);
    goto exit;
  }

  if (!atclient_stringutils_starts_with(recv, recvlen, "data:", strlen("data:"))) {
    ret = 1;
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atclient_connection_send: %d\n", ret);
    goto exit;
  }

  ret = 0;
  goto exit;
exit: { return ret; }
}