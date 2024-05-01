#include "functional_tests/helpers.h"
#include "functional_tests/config.h"
#include <atclient/atclient.h>
#include <atlogger/atlogger.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define TAG "functional_tests_helpers"

int functional_tests_pkam_auth(atclient *atclient, const char *atsign) {
  int ret = 1;

  atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_INFO, "functional_tests_pkam_auth Begin\n");

  const size_t atkeysfilepathsize = 1024;
  char atkeysfilepath[atkeysfilepathsize];
  memset(atkeysfilepath, 0, sizeof(char) * atkeysfilepathsize);
  size_t atkeysfilepathlen = 0;

  atclient_connection root_connection;
  atclient_connection_init(&root_connection);

  atclient_atkeys atkeys;
  atclient_atkeys_init(&atkeys);

  atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_INFO, "atsign: \"%s\"\n", atsign);

  if ((ret = functional_tests_get_atkeys_path(atsign, strlen(atsign), atkeysfilepath, atkeysfilepathsize, &atkeysfilepathlen)) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "functional_tests_get_atkeys_path: %d\n", ret);
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
  atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_INFO, "functional_tests_pkam_auth End (%d)\n", ret);
  return ret;
}
}

int functional_tests_atkey_should_not_exist(atclient *atclient, const char *key, const char *sharedby,
                                            const char *knamespace) {
  int ret = 1;

  atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_INFO, "should_not_exist Begin\n");

  atclient_atkey atkey;
  atclient_atkey_init(&atkey);

  const short atkeystrsize = 128;
  char atkeystr[atkeystrsize];
  memset(atkeystr, 0, sizeof(char) * atkeystrsize);
  size_t atkeystrlen = 0;

  const size_t valuesize = 8;
  char value[valuesize];
  memset(value, 0, sizeof(char) * valuesize);
  size_t valuelen = 0;

  if (knamespace == NULL) {
    snprintf(atkeystr, atkeystrsize, "%s%s", key, sharedby);
  } else {
    snprintf(atkeystr, atkeystrsize, "%s.%s%s", key, knamespace, sharedby);
  }

  if ((ret = atclient_atkey_from_string(&atkey, atkeystr, strlen(atkeystr))) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atclient_atkey_from_string: %d\n", ret);
    goto exit;
  }

  if ((ret = atclient_get_selfkey(atclient, &atkey, value, valuesize, &valuelen)) == 0) {
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

int functional_tests_delete_atkey(atclient *atclient, const char *key, const char *sharedby, const char *knamespace) {
  int ret = 1;

  atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_INFO, "delete Begin\n");

  atclient_atkey atkey;
  atclient_atkey_init(&atkey);

  if ((ret = atclient_atkey_create_selfkey(&atkey, key, strlen(key), sharedby, strlen(sharedby), knamespace,
                                           knamespace == NULL ? 0 : strlen(knamespace))) != 0) {
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
