#include "atauth/send_enroll_request.h"
#include "atclient/atclient.h"
#include "atcommons/enroll_namespace.h"
#include "atcommons/enroll_params.h"
#include "atcommons/enroll_status.h"
#include "atlogger/atlogger.h"
#include <atclient/atclient_utils.h>
#include <atclient/constants.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define TAG "send_enroll_req_example"
#define ATSIGN "@relaxed66"

int create_new_atserver_connection(atclient *ctx, const char *atsign);

int main() {
  atlogger_set_logging_level(ATLOGGER_LOGGING_LEVEL_DEBUG);
  atclient client;
  atclient_init(&client);

  // create new connection to atserver
  int ret = create_new_atserver_connection(&client, ATSIGN);
  if (ret != 0) {
    return ret;
  }

  atcommons_enroll_namespace_t namespace1 = {"kingslanding", "rw"};
  atcommons_enroll_namespace_t namespace2 = {"winterfell", "r"};

  // Allocate memory for ns_list with initial size for 2 namespaces
  atcommons_enroll_namespace_list_t *ns_list =
      malloc(sizeof(atcommons_enroll_namespace_list_t) + sizeof(atcommons_enroll_namespace_t *) * 2);
  if (!ns_list) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "Failed to allocate memory for namespace list\n");
    return -1;
  }
  memset(ns_list, 0, sizeof(atcommons_enroll_namespace_list_t));
  ns_list->length = 0;

  // Append namespaces to ns_list
  ret = atcommons_enroll_namespace_list_append(&ns_list, &namespace1);
  ret = atcommons_enroll_namespace_list_append(&ns_list, &namespace2);
  ret = atcommons_enroll_namespace_list_append(&ns_list, &(atcommons_enroll_namespace_t){"riverlands", "rw"});

  // Allocate and initialize atcommons_enroll_params_t
  atcommons_enroll_params_t *params = malloc(sizeof(atcommons_enroll_params_t));
  if (!params) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "Failed to allocate memory for atcommons_enroll_params_t\n");
    free(ns_list);
    return -1;
  }
  atcommons_enroll_params_init(params);

  // Assign parameters
  params->app_name = "test-app";
  params->device_name = "test-device";
  params->otp = "MU8UBX"; // Note: A new OTP needs to be fetched using the OTP verb from the concerned atsign
  params->ns_list = ns_list;
  params->apkam_public_key = ""; // Note: a base64 encoded RSA2048 public key needs to be provided
  params->apkam_keys_expiry_in_millis = 1000;

  atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_INFO, "Initialization success\n");

  // Allocate memory for enroll_id and send the enroll request
  char enroll_id[ENROLL_ID_MAX_LEN];
  char enroll_status[ATCOMMONS_ENROLL_STATUS_STRING_MAX_LEN];

  ret = atauth_send_enroll_request(&client, params, enroll_id, enroll_status);
  printf("Final ret: %d\n", ret);
  if (ret == 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_INFO, "Enroll ID: %s\tEnroll status: %s\n", enroll_id, enroll_status);
  } else {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "Enroll request failed\n");
  }

  // Clean up
  free(ns_list);
  free(params);

  return ret;
}

int create_new_atserver_connection(atclient *ctx, const char *atsign) {
  char *atserver_host = NULL;
  int atserver_port = 0, ret = 0;

  atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_INFO, "Fetching secondary server address for atsign: %s\n", atsign);
  if ((ret = atclient_utils_find_atserver_address(ATCLIENT_ATDIRECTORY_PRODUCTION_HOST,
                                                  ATCLIENT_ATDIRECTORY_PRODUCTION_PORT, atsign, &atserver_host,
                                                  &atserver_port)) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_DEBUG, "atclient_utils_find_atserver_address: %d\n", ret);
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR,
                 "Could not fetch secondary address for atsign: %s on root directory: %s:%d\n", atsign,
                 ATCLIENT_ATDIRECTORY_PRODUCTION_HOST, ATCLIENT_ATDIRECTORY_PRODUCTION_PORT);
    goto exit;
  }

  if ((ret = atclient_start_atserver_connection(ctx, atserver_host, atserver_port)) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_DEBUG, "atclient_start_atserver_connection: %d\n", ret);
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "Could not connect to secondary server at %s:%d\n", atserver_host,
                 atserver_port);
  }

exit: { return ret; }
}
