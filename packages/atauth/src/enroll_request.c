#include "enroll_request.h"
#include "atlogger/atlogger.h"
#include "enroll_operation.h"
#include "enroll_params.h"
#include "enroll_response.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define TAG "atauth_enroll_request"

// needed for onboard
// .app_name = ATAUTH_DEFAULT_FIRST_APP_NAME,
// .device_name = ATAUTH_DEFAULT_FIRST_DEVICE_NAME,
// .apkam_public_key = apkam_keys.pkam_public_key_base64,
//
// needed for enroll
// app_name from cli
// device_name from cli
//
// encrypted APKAM symmetric key (encrypted with downloaded)
//
//
// raw keys of everything else

int atauth_generate_enroll_command_string(const atauth_enroll_params_t *params,
                                          const atauth_enroll_operation_t operation, char **command_string) {
  int ret = 0;
  size_t cmd_len = strlen("enroll:");

  const char *operation_string = atauth_enroll_operation_map[operation];
  size_t operation_len = strlen(operation_string);

  cmd_len += operation_len + 1; // <operation>:

  char *params_json;
  ret = atauth_enroll_params_to_json(params, &params_json);
  if (ret != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "Failed to jsonify enroll params\n");
    return ret;
  }

  size_t params_json_len = strlen(params_json);
  cmd_len += params_json_len + 2; // { <json> }\n\0
  *command_string = malloc(sizeof(char) * cmd_len + 1);
  if (*command_string == NULL) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "Failed to allocate enroll command string\n");
    free(params_json);
    return 1;
  }

  snprintf(*command_string, cmd_len, "enroll:%s:%s\n", operation_string, params_json);
  free(params_json);
  (*command_string)[cmd_len] = 0;
  return 0;
}

int atauth_send_enroll_request(atclient *atclient, const atauth_enroll_params_t *params,
                               const atauth_enroll_operation_t operation, struct enroll_response *response) {
  int ret = 0;

  char *command;
  ret = atauth_generate_enroll_command_string(params, operation, &command);
  if (ret != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "Failed to generate enroll command string\n");
    return ret;
  }

  unsigned char recv[300];
  size_t recv_len;
  ret = atclient_connection_send(&atclient->atserver_connection, (unsigned char *)command, strlen(command), recv, 300,
                                 &recv_len);
  free(command);
  if (ret != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "Failed to send enroll command to atserver: %d\n", ret);
    return ret;
  }

  ret = parse_enrollment_response((const char *)recv, response);

  return ret;
}
