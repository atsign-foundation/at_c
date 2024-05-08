#include "functional_tests/helpers.h"
#include "functional_tests/config.h"
#include <atclient/atclient.h>
#include <atclient/stringutils.h>
#include <atclient/constants.h>
#include <atlogger/atlogger.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define TAG "functional_tests_helpers"

int functional_tests_set_up_atkeys(atclient_atkeys *atkeys, const char *atsign, const size_t atsignlen) {
  int ret = 1;

  const size_t atkeyspathsize = 1024;
  char atkeyspath[atkeyspathsize];
  memset(atkeyspath, 0, atkeyspathsize);
  size_t atkeyspathlen = 0;

  ret = functional_tests_get_atkeys_path(atsign, atsignlen, atkeyspath, atkeyspathsize, &atkeyspathlen);
  if (ret != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "Failed to get atkeys_sharedwith path: %d\n", ret);
    goto exit;
  }

  if ((ret = atclient_atkeys_populate_from_path(atkeys, atkeyspath)) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "Failed to populate atkeys_sharedwith from path: %d\n", ret);
    goto exit;
  }

  goto exit;

exit: { return ret; }
}

int functional_tests_pkam_auth(atclient *atclient, atclient_atkeys *atkeys, const char *atsign, const size_t atsignlen) {
  int ret = 1;

  atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_INFO, "functional_tests_pkam_auth Begin\n");

  atclient_connection root_connection;
  atclient_connection_init(&root_connection);

  if ((ret = atclient_connection_connect(&root_connection, ROOT_HOST, ROOT_PORT)) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atclient_connection_connect: %d\n", ret);
    goto exit;
  }
  atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_INFO, "root connection established\n");

  if ((ret = atclient_pkam_authenticate(atclient, &root_connection, atkeys, atsign)) != 0) {
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

  if (!atclient_stringutils_starts_with(recv, recvlen, "data:", 5)) {
    ret = false;
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_INFO, "publickey does not exist: \"%s\"\n", recv);
    goto exit;
  }

  if (recvlen <= 0) {
    ret = -1;
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_INFO, "error occured with recvlen <= 0: %lu. Recv: \"%s\"\n", recvlen,
                 recv);
    goto exit;
  }

  ret = true;
  goto exit;
exit: { return ret; }
}

int functional_tests_selfkey_exists(atclient *atclient, const char *key, const char *sharedby, const char *knamespace) {
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

  if (!atclient_stringutils_starts_with(recv, recvlen, "data:", 5)) {
    ret = false;
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_INFO, "selfkey does not exist: \"%s\"\n", recv);
    goto exit;
  }

  if (recvlen <= 0) {
    ret = -1;
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_INFO, "selfkey does not exist (%lu): \"%s\"\n", recvlen, recv);
    goto exit;
  }

  ret = true;
  goto exit;
exit: { return ret; }
}

int functional_tests_sharedkey_exists(atclient *atclient, const char *key, const char *sharedby, const char *sharedwith,
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
    snprintf(atkeystr, atkeystrsize, "%s:%s%s", sharedwith, key, sharedby);
  } else {
    snprintf(atkeystr, atkeystrsize, "%s:%s.%s%s", sharedwith, key, knamespace, sharedby);
  }

  snprintf(command, commandsize, "lookup:%s\r\n", atkeystr);
  commandlen = strlen(command);

  if ((ret = atclient_connection_send(&(atclient->secondary_connection), (unsigned char *)command, commandlen,
                                      (unsigned char *)recv, recvsize, &recvlen)) != 0) {
    ret = -1;
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atclient_connection_send: %d\n", ret);
    goto exit;
  }

  if (!atclient_stringutils_starts_with(recv, recvlen, "data:", 5)) {
    ret = false;
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_INFO, "sharedkey does not exist: \"%s\"\n", recv);
    goto exit;
  }

  if (recvlen <= 0) {
    ret = -1;
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_INFO, "sharedkey does not exist (%lu): \"%s\"\n", recvlen, recv);
    goto exit;
  }

  ret = true;
  goto exit;
exit: { return ret; }
}

int functional_tests_tear_down_sharedenckeys(atclient *atclient1, const char *recipient)
{
    int ret = 1;

    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_INFO, "tear_down Begin\n");

    char atkeystrtemp[ATCLIENT_ATKEY_FULL_LEN];

    atclient_atkey atkeyforme;
    atclient_atkey_init(&atkeyforme);

    atclient_atkey atkeyforthem;
    atclient_atkey_init(&atkeyforthem);

    memset(atkeystrtemp, 0, sizeof(char) * ATCLIENT_ATKEY_FULL_LEN);
    snprintf(atkeystrtemp, ATCLIENT_ATKEY_FULL_LEN, "shared_key.%s%s", (recipient+1), atclient1->atsign.atsign);
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_INFO, "atkeystrtemp: \"%s\"\n", atkeystrtemp);
    if((ret = atclient_atkey_from_string(&atkeyforme, atkeystrtemp, strlen(atkeystrtemp))) != 0)
    {
        atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atclient_atkey_from_string: %d\n", ret);
        goto exit;
    }

    memset(atkeystrtemp, 0, sizeof(char) * ATCLIENT_ATKEY_FULL_LEN);
    snprintf(atkeystrtemp, ATCLIENT_ATKEY_FULL_LEN, "%s:shared_key%s", recipient, atclient1->atsign.atsign);
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_INFO, "atkeystrtemp: \"%s\"\n", atkeystrtemp);
    if((ret = atclient_atkey_from_string(&atkeyforthem, atkeystrtemp, strlen(atkeystrtemp))) != 0)
    {
        atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atclient_atkey_from_string: %d\n", ret);
        goto exit;
    }

    if((ret = atclient_delete(atclient1, &atkeyforme)) != 0)
    {
        atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atclient_delete: %d\n", ret);
        goto exit;
    }
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_INFO, "deleted shared enc key for me\n");

    if((ret = atclient_delete(atclient1, &atkeyforthem)) != 0)
    {
        atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atclient_delete: %d\n", ret);
        goto exit;
    }
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_INFO, "deleted shared enc key for them\n");

    ret = 0;
    goto exit;

exit: {
    atclient_atkey_free(&atkeyforme);
    atclient_atkey_free(&atkeyforthem);
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_INFO, "tear_down End (%d)\n", ret);
    return ret;
}
}
