#include "functional_tests/config.h"
#include "functional_tests/helpers.h"
#include <atclient/atclient.h>
#include <atclient/stringutils.h>
#include <atlogger/atlogger.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define TAG "test_atclient_publickey"

#define ATKEY_NAME "test_atclient_publickey"
#define ATKEY_NAMESPACE "functional_tests"
#define ATKEY_SHAREDBY SECOND_ATSIGN
#define ATKEY_VALUE "my public value"
#define ATKEY_CCD true          // cascade delete
#define ATKEY_TTL 1000 * 60 * 5 // 5 minutes
#define ATKEY_TTR -1            // do not cache
#define ATKEY_ISENCRYPTED false
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
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "Failed to authenticate with PKAM: %d\n", ret);
    goto exit;
  }

  if ((ret = test_1_should_not_exist(&atclient)) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "Failed test_1_should_not_exist: %d\n", ret);
    goto exit;
  }

  if ((ret = test_2_put(&atclient)) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "Failed test_2_put: %d\n", ret);
    goto exit;
  }

  if ((ret = test_3_get(&atclient)) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "Failed test_3_get: %d\n", ret);
    goto exit;
  }

  if ((ret = test_4_delete(&atclient)) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "Failed test_4_delete: %d\n", ret);
    goto exit;
  }

  if ((ret = test_5_should_not_exist(&atclient)) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "Failed test_5_should_not_exist: %d\n", ret);
    goto exit;
  }

  if ((ret = test_6_put_with_metadata(&atclient)) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "Failed test_6_put_with_metadata: %d\n", ret);
    goto exit;
  }

  if ((ret = test_7_get_with_metadata(&atclient)) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "Failed test_7_get_with_metadata: %d\n", ret);
    goto exit;
  }

  if ((ret = test_8_delete(&atclient)) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "Failed test_8_delete: %d\n", ret);
    goto exit;
  }

  if ((ret = test_9_should_not_exist(&atclient)) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "Failed test_9_should_not_exist: %d\n", ret);
    goto exit;
  }

  ret = 0;

  goto exit;
exit: {
  atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_INFO, "tear_down: %d\n", tear_down(&atclient));
  atclient_free(&atclient);
  atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_INFO, "End (%d)\n", ret);
  return ret;
}
}

static int test_1_should_not_exist(atclient *atclient) {
  int ret = 1;

  atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_INFO, "test_1_should_not_exist Begin\n");

  if (functional_tests_publickey_exists(atclient, ATKEY_NAME, ATKEY_SHAREDBY, ATKEY_NAMESPACE)) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "Failed functional_tests_publickey_exists when it shouldn't: %d\n",
                 ret);
    ret = 1;
    goto exit;
  }

  atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_INFO, "AtKey doesn't exist, which is expected. (%d)\n", ret);

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

  if ((ret = atclient_atkey_create_publickey(&atkey, ATKEY_NAME, strlen(ATKEY_NAME), ATKEY_SHAREDBY,
                                             strlen(ATKEY_SHAREDBY), ATKEY_NAMESPACE, strlen(ATKEY_NAMESPACE))) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "Failed atclient_atkey_create_publickey");
    goto exit;
  }

  if ((ret = atclient_put(atclient, &atkey, ATKEY_VALUE, strlen(ATKEY_VALUE), NULL)) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "Failed atclient_put");
    goto exit;
  }

  atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_INFO, "Done put.\n");

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

  const size_t valuesize = 1024;
  char value[valuesize];
  memset(value, 0, sizeof(char) * valuesize);
  size_t valuelen = 0;

  if ((ret = atclient_atkey_create_publickey(&atkey, ATKEY_NAME, strlen(ATKEY_NAME), ATKEY_SHAREDBY,
                                             strlen(ATKEY_SHAREDBY), ATKEY_NAMESPACE,
                                             ATKEY_NAMESPACE == NULL ? 0 : strlen(ATKEY_NAMESPACE))) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "Failed atclient_atkey_create_publickey");
    goto exit;
  }

  if ((ret = atclient_get_publickey(atclient, &atkey, value, valuesize, &valuelen, false)) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "Failed atclient_get_publickey");
    goto exit;
  }
  atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_INFO, "value: \"%s\"\n", value);

  if (strcmp(value, ATKEY_VALUE) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "Failed value comparison");
    goto exit;
  }

  atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_INFO, "value: \"%s\" == \"%s\"\n", value, ATKEY_VALUE);

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

  if ((ret = atclient_atkey_create_publickey(&atkey, ATKEY_NAME, strlen(ATKEY_NAME), ATKEY_SHAREDBY,
                                             strlen(ATKEY_SHAREDBY), ATKEY_NAMESPACE,
                                             ATKEY_NAMESPACE == NULL ? 0 : strlen(ATKEY_NAMESPACE))) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "Failed atclient_atkey_create_publickey");
    goto exit;
  }

  if ((ret = atclient_delete(atclient, &atkey)) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "Failed atclient_delete");
    goto exit;
  }

  atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_INFO, "Done delete.\n");

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

  if ((ret = functional_tests_publickey_exists(atclient, ATKEY_NAME, ATKEY_SHAREDBY, ATKEY_NAMESPACE)) != false) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "Failed functional_tests_atkey_should_not_exist: %d\n", ret);
    goto exit;
  }

  atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_INFO, "AtKey doesn't exist, which is expected. (%d)\n", ret);

  ret = 0;

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

  if ((ret = atclient_atkey_create_publickey(&atkey, ATKEY_NAME, strlen(ATKEY_NAME), ATKEY_SHAREDBY,
                                             strlen(ATKEY_SHAREDBY), ATKEY_NAMESPACE,
                                             ATKEY_NAMESPACE == NULL ? 0 : strlen(ATKEY_NAMESPACE))) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "Failed atclient_atkey_create_publickey");
    goto exit;
  }

  atclient_atkey_metadata_set_ccd(&(atkey.metadata), ATKEY_CCD);
  atclient_atkey_metadata_set_ttl(&(atkey.metadata), ATKEY_TTL);
  atclient_atkey_metadata_set_ttr(&(atkey.metadata), ATKEY_TTR);
  atclient_atkey_metadata_set_isencrypted(&(atkey.metadata), ATKEY_ISENCRYPTED);
  atclient_atkey_metadata_set_isbinary(&(atkey.metadata), ATKEY_ISBINARY);

  if ((ret = atclient_put(atclient, &atkey, ATKEY_VALUE, strlen(ATKEY_VALUE), NULL)) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "Failed atclient_put");
    goto exit;
  }

  atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_INFO, "Done put.\n");

  goto exit;

exit: {
  atclient_atkey_free(&atkey);
  return ret;
}
}

static int test_7_get_with_metadata(atclient *atclient) {
  int ret = 1;

  atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_INFO, "test_7_get_with_metadata Begin\n");

  atclient_atkey atkey;
  atclient_atkey_init(&atkey);

  const size_t valuesize = 1024;
  char value[valuesize];
  memset(value, 0, sizeof(char) * valuesize);
  size_t valuelen = 0;

  if ((ret = atclient_atkey_create_publickey(&atkey, ATKEY_NAME, strlen(ATKEY_NAME), ATKEY_SHAREDBY,
                                             strlen(ATKEY_SHAREDBY), ATKEY_NAMESPACE,
                                             ATKEY_NAMESPACE == NULL ? 0 : strlen(ATKEY_NAMESPACE))) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "Failed atclient_atkey_create_publickey");
    goto exit;
  }

  if ((ret = atclient_get_publickey(atclient, &atkey, value, valuesize, &valuelen, true)) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "Failed atclient_get_publickey");
    goto exit;
  }

  if (strcmp(value, ATKEY_VALUE) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "Failed value comparison, got %s and expected %s\n", value,
                 ATKEY_VALUE);
    goto exit;
  }
  atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_INFO, "value: \"%s\"\n", value);

  if (atkey.metadata.ccd != ATKEY_CCD) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "Failed ccd comparison, got %d and expected %d\n",
                 atkey.metadata.ccd, ATKEY_CCD);
    goto exit;
  }
  atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_INFO, "atkey.metadata.ccd: %d\n", atkey.metadata.ccd);

  if (atkey.metadata.ttl != ATKEY_TTL) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "Failed ttl comparison, got %d and expected %d\n",
                 atkey.metadata.ttl, ATKEY_TTL);
    goto exit;
  }
  atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_INFO, "atkey.metadata.ttl: %d\n", atkey.metadata.ttl);

  if (atkey.metadata.ttr != ATKEY_TTR) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "Failed ttr comparison, got %d and expected %d\n",
                 atkey.metadata.ttr, ATKEY_TTR);
    goto exit;
  }
  atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_INFO, "atkey.metadata.ttr: %d\n", atkey.metadata.ttr);

  if (atkey.metadata.isencrypted != ATKEY_ISENCRYPTED) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "Failed isencrypted comparison, got %d and expected %d\n",
                 atkey.metadata.isencrypted, ATKEY_ISENCRYPTED);
    goto exit;
  }
  atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_INFO, "atkey.metadata.isencrypted: %d\n", atkey.metadata.isencrypted);

  if (atkey.metadata.isbinary != ATKEY_ISBINARY) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "Failed isbinary comparison, got %d and expected %d\n",
                 atkey.metadata.isbinary, ATKEY_ISBINARY);
    goto exit;
  }
  atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_INFO, "atkey.metadata.isbinary: %d\n", atkey.metadata.isbinary);

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

  atclient_atkey atkey;
  atclient_atkey_init(&atkey);

  if ((ret = atclient_atkey_create_publickey(&atkey, ATKEY_NAME, strlen(ATKEY_NAME), ATKEY_SHAREDBY,
                                             strlen(ATKEY_SHAREDBY), ATKEY_NAMESPACE,
                                             ATKEY_NAMESPACE == NULL ? 0 : strlen(ATKEY_NAMESPACE))) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "Failed atclient_atkey_create_publickey");
    goto exit;
  }

  if ((ret = atclient_delete(atclient, &atkey)) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "Failed atclient_delete");
    goto exit;
  }

  goto exit;
exit: {
  atclient_atkey_free(&atkey);
  atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_INFO, "test_8_delete End (%d)\n", ret);
  return ret;
}
}

static int test_9_should_not_exist(atclient *atclient) {
  int ret = 1;

  atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_INFO, "test_9_should_not_exist Begin\n");

  if ((ret = functional_tests_publickey_exists(atclient, ATKEY_NAME, ATKEY_SHAREDBY, ATKEY_NAMESPACE)) != false) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "Failed functional_tests_atkey_should_not_exist");
    goto exit;
  }

  ret = 0;

  goto exit;
exit: {
  atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_INFO, "test_9_should_not_exist End (%d)\n", ret);
  return ret;
}
}

static int tear_down(atclient *atclient) {
  int ret = 1;

  atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_INFO, "teardown Begin\n");

  const size_t commandsize = 512;
  char command[commandsize];
  memset(command, 0, sizeof(char) * commandsize);
  size_t commandlen = 0;

  const size_t atkeystrsize = 128;
  char atkeystr[atkeystrsize];
  memset(atkeystr, 0, sizeof(char) * atkeystrsize);
  size_t atkeystrlen = 0;

  const size_t recvsize = 256;
  char recv[recvsize];
  memset(recv, 0, sizeof(char) * recvsize);
  size_t recvlen = 0;

  atclient_atkey atkey;
  atclient_atkey_init(&atkey);

  if (ATKEY_NAMESPACE == NULL) {
    snprintf(atkeystr, atkeystrsize, "%s%s", ATKEY_NAME, ATKEY_SHAREDBY);
  } else {
    snprintf(atkeystr, atkeystrsize, "%s.%s%s", ATKEY_NAME, ATKEY_NAMESPACE, ATKEY_SHAREDBY);
  }

  snprintf(command, commandsize, "delete:public:%s\r\n", atkeystr);
  commandlen = strlen(command);

  if ((ret = atclient_connection_send(&(atclient->secondary_connection), (unsigned char *)command, commandlen,
                                      (unsigned char *)recv, recvsize, &recvlen)) != 0) {
    ret = 1;
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atclient_connection_send: %d\n", ret);
    goto exit;
  }

  if (recvlen <= 0) {
    ret = 1;
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_INFO, "recvlen was <= 0: (%lu): \"%s\"\n", recvlen, recv);
    goto exit;
  }

  if (!atclient_stringutils_starts_with(recv, recvlen, "data:", strlen("data:"))) {
    ret = 1;
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_INFO, "Failed to delete: \"%.*s\"\n", (int)recvlen, recv);
    goto exit;
  }

  ret = 0;
  goto exit;
exit: {
  atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_INFO, "teardown End (%d)\n", ret);
  return ret;
}
}