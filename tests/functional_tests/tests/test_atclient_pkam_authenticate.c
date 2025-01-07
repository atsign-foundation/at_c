#include "atclient/request_options.h"
#include "functional_tests/config.h"
#include <atclient/atclient.h>
#include <atclient/atclient_utils.h>
#include <atclient/atkeys_file.h>
#include <atclient/constants.h>
#include <atlogger/atlogger.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static const size_t atkeyspathsize = 1024;
static char atkeyspath[1024];
static char *atsign;

static int test1_pkam_no_options();
static int test2_pkam_with_options();
// TODO: add apkam enrollment
// - can't do this as a unit test until we have at_activate in C
// static int test3_apkam_enrollment();

int main() {
  int ret = 0;

  atsign = FIRST_ATSIGN;

  atlogger_set_logging_level(ATLOGGER_LOGGING_LEVEL_DEBUG);

  memset(atkeyspath, 0, atkeyspathsize);
  size_t atkeyspathlen = 0;

  if ((ret = functional_tests_get_atkeys_path(atsign, strlen(atsign), atkeyspath, atkeyspathsize, &atkeyspathlen)) !=
      0) {
    atlogger_log("pkam_authenticate main", ATLOGGER_LOGGING_LEVEL_ERROR, "Failed to get atkeys_sharedwith path: %d\n",
                 ret);
    return ret;
  }

  ret += test1_pkam_no_options();
  ret += test2_pkam_with_options();

  return ret;
}

static int test1_pkam_no_options() {
  const char *tag = "test1_pkam_no_options";
  int ret = 0;

  atclient_atkeys_file atkeys_file;
  atclient_atkeys_file_init(&atkeys_file);

  atclient_atkeys atkeys;
  atclient_atkeys_init(&atkeys);

  atclient atclient;
  atclient_init(&atclient);

  atclient_authenticate_options authenticate_options;
  atclient_authenticate_options_init(&authenticate_options);

  if((ret = atclient_authenticate_options_set_atdirectory_host(&authenticate_options, ATDIRECTORY_HOST)) != 0) {
    return ret;
  }

  if((ret = atclient_authenticate_options_set_atdirectory_port(&authenticate_options, ATDIRECTORY_PORT)) != 0) {
    return ret;
  }

  if ((ret = atclient_atkeys_file_from_path(&atkeys_file, atkeyspath)) != 0) {
    return ret;
  }
  atlogger_log(tag, ATLOGGER_LOGGING_LEVEL_INFO, "atclient_atkeys_file_from_string: %d\n", ret);

  if ((ret = atclient_atkeys_populate_from_atkeys_file(&atkeys, &atkeys_file)) != 0) {
    return ret;
  }
  atlogger_log(tag, ATLOGGER_LOGGING_LEVEL_INFO, "atclient_atkeys_populate_from_atkeys_file: %d\n", ret);

  if ((ret = atclient_pkam_authenticate(&atclient, atsign, &atkeys, &authenticate_options, NULL)) != 0) {
    atlogger_log(tag, ATLOGGER_LOGGING_LEVEL_ERROR, "Failed to authenticate\n");
    return ret;
  } else {
    atlogger_log(tag, ATLOGGER_LOGGING_LEVEL_DEBUG, "Authenticated\n");
  }

  atclient_authenticate_options_free(&authenticate_options);
  return ret;
}

static int test2_pkam_with_options() {
  const char *tag = "test2_pkam_with_options";
  int ret = 0;

  atclient_atkeys_file atkeys_file;
  atclient_atkeys_file_init(&atkeys_file);

  atclient_atkeys atkeys;
  atclient_atkeys_init(&atkeys);

  atclient atclient;
  atclient_init(&atclient);

  atclient_authenticate_options options;
  atclient_authenticate_options_init(&options);

  char *atserver_host = NULL;
  int atserver_port = 0;

  if ((ret = atclient_atkeys_file_from_path(&atkeys_file, atkeyspath)) != 0) {
    return ret;
  }
  atlogger_log(tag, ATLOGGER_LOGGING_LEVEL_INFO, "atclient_atkeys_file_from_string: %d\n", ret);

  if ((ret = atclient_atkeys_populate_from_atkeys_file(&atkeys, &atkeys_file)) != 0) {
    return ret;
  }
  atlogger_log(tag, ATLOGGER_LOGGING_LEVEL_INFO, "atclient_atkeys_populate_from_atkeys_file: %d\n", ret);

  if ((ret = atclient_utils_find_atserver_address(ATDIRECTORY_HOST,
                                                  ATDIRECTORY_PORT, atsign, &atserver_host,
                                                  &atserver_port)) != 0) {
    atlogger_log(tag, ATLOGGER_LOGGING_LEVEL_ERROR, "atclient_utils_find_atserver_address: %d\n", ret);
    return ret;
  }

  if ((ret = atclient_authenticate_options_set_atserver_host(&options, atserver_host)) != 0) {
    return ret;
  }

  if ((ret = atclient_authenticate_options_set_atserver_port(&options, atserver_port)) != 0) {
    return ret;
  }

  if ((ret = atclient_pkam_authenticate(&atclient, atsign, &atkeys, &options, NULL)) != 0) {
    atlogger_log(tag, ATLOGGER_LOGGING_LEVEL_ERROR, "Failed to authenticate\n");
    return ret;
  } else {
    atlogger_log(tag, ATLOGGER_LOGGING_LEVEL_DEBUG, "Authenticated\n");
  }

  atclient_authenticate_options_free(&options);
  atclient_atkeys_file_free(&atkeys_file);
  atclient_atkeys_free(&atkeys);
  atclient_free(&atclient);
  free(atserver_host);

  return ret;
}
