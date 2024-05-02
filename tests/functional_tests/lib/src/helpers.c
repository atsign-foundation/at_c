#include "functional_tests/helpers.h"
#include "functional_tests/config.h"
#include <atclient/atclient.h>
#include <atclient/stringutils.h>
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

  if ((ret = functional_tests_get_atkeys_path(atsign, strlen(atsign), atkeysfilepath, atkeysfilepathsize,
                                              &atkeysfilepathlen)) != 0) {
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

int functional_tests_publickey_exists(atclient *atclient, const char *key, const char *sharedby,
                                                const char *knamespace) {
  int ret = -1;

  atclient_atkey atkey;
  atclient_atkey_init(&atkey);

  const short atkeystrsize = 128;
  char atkeystr[atkeystrsize];
  memset(atkeystr, 0, sizeof(char) * atkeystrsize);
  size_t atkeystrlen = 0;

  const short commandsize = 256;
  char command[commandsize];
  memset(command, 0, sizeof(char) * commandsize);
  size_t commandlen = 0;

  const size_t recvsize = 256;
  char recv[recvsize];
  memset(recv, 0, sizeof(char) * recvsize);
  size_t recvlen = 0;

  if (knamespace == NULL) {
    snprintf(atkeystr, atkeystrsize, "%s%s", key, sharedby);
  } else {
    snprintf(atkeystr, atkeystrsize, "%s.%s%s", key, knamespace, sharedby);
  }

  snprintf(command, commandsize, "plookup:%s\r\n", atkeystr);
  commandlen = strlen(command);

  if ((ret = atclient_connection_send(&(atclient->secondary_connection), (unsigned char *)command, commandlen,
                                      (unsigned char *)recv, recvsize, &recvlen)) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atclient_connection_send: %d\n", ret);
    goto exit;
  }

  if(!atclient_stringutils_starts_with(recv, recvlen, "data:", 5)) {
    ret = false;
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_INFO, "publickey does not exist: \"%s\"\n", recv);
    goto exit;
  }

  if(recvlen <= 0)
  {
    ret = -1;
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_INFO, "error occured with recvlen <= 0: %lu. Recv: \"%s\"\n", recvlen, recv);
    goto exit;
  }

  ret = true;
  goto exit;
exit: {
  return ret;
}
}

int functional_tests_selfkey_exists(atclient *atclient, const char *key, const char *sharedby,
                                              const char *knamespace) {
  int ret = -1;

  atclient_atkey atkey;
  atclient_atkey_init(&atkey);

  const short atkeystrsize = 128;
  char atkeystr[atkeystrsize];
  memset(atkeystr, 0, sizeof(char) * atkeystrsize);
  size_t atkeystrlen = 0;

  const short commandsize = 256;
  char command[commandsize];
  memset(command, 0, sizeof(char) * commandsize);
  size_t commandlen = 0;

  const size_t recvsize = 256;
  char recv[recvsize];
  memset(recv, 0, sizeof(char) * recvsize);
  size_t recvlen = 0;

  if (knamespace == NULL) {
    snprintf(atkeystr, atkeystrsize, "%s%s", key, sharedby);
  } else {
    snprintf(atkeystr, atkeystrsize, "%s.%s%s", key, knamespace, sharedby);
  }

  snprintf(command, commandsize, "llookup:%s\r\n", atkeystr);
  commandlen = strlen(command);

  if ((ret = atclient_connection_send(&(atclient->secondary_connection), (unsigned char *)command, commandlen,
                                      (unsigned char *)recv, recvsize, &recvlen)) != 0) {
    ret = -1;
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atclient_connection_send: %d\n", ret);
    goto exit;
  }

  if(!atclient_stringutils_starts_with(recv, recvlen, "data:", 5)) {
    ret = false;
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_INFO, "selfkey does not exist: \"%s\"\n", recv);
    goto exit;
  }

  if(recvlen <= 0)
  {
    ret = -1;
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_INFO, "selfkey does not exist (%lu): \"%s\"\n", recvlen, recv);
    goto exit;
  }

  ret = true;
  goto exit;
exit: {
  return ret;
}
}

int functional_tests_sharedkey_exists(atclient *atclient, const char *key, const char *sharedby,
                                                const char *sharedwith, const char *knamespace) {
  int ret = -1;

  atclient_atkey atkey;
  atclient_atkey_init(&atkey);

  const short atkeystrsize = 128;
  char atkeystr[atkeystrsize];
  memset(atkeystr, 0, sizeof(char) * atkeystrsize);
  size_t atkeystrlen = 0;

  const short commandsize = 256;
  char command[commandsize];
  memset(command, 0, sizeof(char) * commandsize);
  size_t commandlen = 0;

  const size_t recvsize = 256;
  char recv[recvsize];
  memset(recv, 0, sizeof(char) * recvsize);
  size_t recvlen = 0;

  if (knamespace == NULL) {
    snprintf(atkeystr, atkeystrsize, "%s:%s%s", sharedwith, key, sharedby);
  } else {
    snprintf(atkeystr, atkeystrsize, "%s:%s.%s%s", sharedwith, key, knamespace, sharedby);
  }

  snprintf(command, commandsize, "lookup:%s\r\n", atkeystr);
  commandlen = strlen(command);

  if((ret = atclient_connection_send(&(atclient->secondary_connection), (unsigned char *)command, commandlen,
                                      (unsigned char *)recv, recvsize, &recvlen)) != 0) {
    ret = -1;
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atclient_connection_send: %d\n", ret);
    goto exit;
  }

  if(!atclient_stringutils_starts_with(recv, recvlen, "data:", 5)) {
    ret = false;
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_INFO, "sharedkey does not exist: \"%s\"\n", recv);
    goto exit;
  }

  if(recvlen <= 0)
  {
    ret = -1;
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_INFO, "sharedkey does not exist (%lu): \"%s\"\n", recvlen, recv);
    goto exit;
  }

  ret = true;
  goto exit;
exit: {
  return ret;
}
}
