#include <atclient/atclient_utils.h>
#include <atlogger/atlogger.h>
#include <stdlib.h>
#include <string.h>

#define ATDIRECTORY_HOST "root.atsign.org"
#define ATDIRECTORY_PORT 64

#define ATSIGN "@12alpaca"

#define TAG "test_atclient_find_atserver_address"

#define EXPECTED_HOST "228aafb0-94d3-5aa2-a3b3-e36af115480d.swarm0002.atsign.zone"
#define EXPECTED_PORT 6943

static int test_1_find_atserver_address_should_pass();

int main() {
  int ret = 1;

  atlogger_set_logging_level(ATLOGGER_LOGGING_LEVEL_DEBUG);

  if ((ret = test_1_find_atserver_address_should_pass()) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "test_1_find_atserver_address_should_pass: %d\n", ret);
    goto exit;
  }

  ret = 0;
  goto exit;

exit: { return ret; }
}

static int test_1_find_atserver_address_should_pass() {
  int ret = 1;

  atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_INFO, "test_1_find_atserver_address_should_pass Begin\n");

  char *atserver_host = NULL;
  int atserver_port = 0;

  if ((ret = atclient_utils_find_atserver_address(ATDIRECTORY_HOST, ATDIRECTORY_PORT, ATSIGN, &atserver_host,
                                            &atserver_port)) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atclient_find_atserver_address: %d\n", ret);
    goto exit;
  }

  atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_INFO, "atserver_host: %s\n", atserver_host);
  atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_INFO, "atserver_port: %d\n", atserver_port);

    if (strcmp(atserver_host, EXPECTED_HOST) != 0) {
        atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atserver_host doesn't match\n");
        ret = 1;
        goto exit;
    }

    if (atserver_port != EXPECTED_PORT) {
        atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atserver_port doesn't match\n");
        ret = 1;
        goto exit;
    }

  ret = 0;
  goto exit;
exit: { 
    free(atserver_host);
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_INFO, "test_1_find_atserver_address_should_pass End: %d\n", ret);
    return ret; }
}
