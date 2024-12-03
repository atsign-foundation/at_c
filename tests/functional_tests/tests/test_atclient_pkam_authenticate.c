#include "atclient/request_options.h"
#include "functional_tests/config.h"
#include "functional_tests/helpers.h"
#include <atclient/atclient.h>
#include <atclient/atclient_utils.h>
#include <atclient/atkeys_file.h>
#include <atclient/constants.h>
#include <atlogger/atlogger.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define ATSIGN FIRST_ATSIGN

static int test_1_pkam_with_null_options();
static int test_2_pkam_with_options();
// TODO: add apkam enrollment
// - can't do this as a unit test until we have at_activate in C
// static int test3_apkam_enrollment();

int main() {
  int ret = 0;

  atlogger_set_logging_level(ATLOGGER_LOGGING_LEVEL_DEBUG);

  ret += test_1_pkam_with_null_options();
  ret += test_2_pkam_with_options();

exit: { return ret; }
}

static int test_1_pkam_with_null_options() {
  int ret = 1;

  const char *tag = "test_1_pkam_with_null_options";

  atclient_atkeys_file atkeys_file;
  atclient_atkeys_file_init(&atkeys_file);

  atclient_atkeys atkeys;
  atclient_atkeys_init(&atkeys);

  atclient atclient;
  atclient_init(&atclient);

  if ((ret = functional_tests_set_up_atkeys(&atkeys, ATSIGN)) != 0) {
    atlogger_log(tag, ATLOGGER_LOGGING_LEVEL_ERROR, "Failed to get atkeys_sharedwith path: %d\n", ret);
    goto exit;
  }

  if ((ret = atclient_pkam_authenticate(&atclient, ATSIGN, &atkeys, NULL)) != 0) {
    atlogger_log(tag, ATLOGGER_LOGGING_LEVEL_ERROR, "Failed to authenticate\n");
    goto exit;
  } else {
    atlogger_log(tag, ATLOGGER_LOGGING_LEVEL_DEBUG, "Authenticated\n");
  }

  ret = 0;
exit: { return ret; }
}

static int test_2_pkam_with_options() {
  int ret = 1;


  const char *tag = "test_2_pkam_with_options";

  atlogger_log(tag, ATLOGGER_LOGGING_LEVEL_INFO, "Begin test_2_pkam_with_options\n");

  atclient_atkeys atkeys;
  atclient_atkeys_init(&atkeys);

  atclient atclient;
  atclient_init(&atclient);

  atclient_authenticate_options options;
  atclient_authenticate_options_init(&options);

  char *atserver_host = NULL;
  int atserver_port = 0;

  if ((ret = functional_tests_set_up_atkeys(&atkeys, ATSIGN)) != 0) {
    atlogger_log(tag, ATLOGGER_LOGGING_LEVEL_ERROR, "Failed to populate atkeys_sharedwith from path: %d\n", ret);
    goto exit;
  }

  if ((ret = atclient_utils_find_atserver_address(ATDIRECTORY_HOST, ATDIRECTORY_PORT, ATSIGN, &atserver_host,
                                                  &atserver_port)) != 0) {
    atlogger_log(tag, ATLOGGER_LOGGING_LEVEL_ERROR, "atclient_utils_find_atserver_address: %d\n", ret);
    goto exit;
  }

  if ((ret = atclient_authenticate_options_set_atserver_host(&options, atserver_host)) != 0) {
    atlogger_log(tag, ATLOGGER_LOGGING_LEVEL_ERROR, "atclient_authenticate_options_set_at_directory_host: %d\n",
                 ret);
    goto exit;
  }

  if ((ret = atclient_authenticate_options_set_atserver_port(&options, atserver_port)) != 0) {
    atlogger_log(tag, ATLOGGER_LOGGING_LEVEL_ERROR, "atclient_authenticate_options_set_at_directory_port: %d\n",
                 ret);
    goto exit;
  }

  if ((ret = atclient_pkam_authenticate(&atclient, ATSIGN, &atkeys, &options) != 0)) {
    atlogger_log(tag, ATLOGGER_LOGGING_LEVEL_ERROR, "Failed to authenticate\n");
    goto exit;
  }

  ret = 0;

exit: { 
  atclient_authenticate_options_free(&options);
  atclient_atkeys_free(&atkeys);
  atclient_free(&atclient);
  atlogger_log(tag, ATLOGGER_LOGGING_LEVEL_INFO, "End test_2_pkam_with_options: %d\n", ret);
  return ret; }
}
