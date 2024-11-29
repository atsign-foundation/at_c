#include "atauth/send_enroll_request.h"

#include "atclient/atclient.h"
#include "atclient/constants.h"
#include "atclient/string_utils.h"
#include "atcommons/enroll_command_builder.h"
#include "atcommons/enroll_operation.h"
#include "atcommons/enroll_params.h"
#include "atlogger/atlogger.h"
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>

#define TAG "send_enroll_request"

int atauth_send_enroll_request(atclient *client, const atcommons_enroll_params_t *ep, char *enroll_id, char *enroll_status) {
  int ret = 0;
  const size_t recv_size = 100; // to hold the response for enroll request
  unsigned char recv[recv_size];
  char *recv_trimmed = NULL;
  size_t recv_len;

  if (enroll_id == NULL) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "enroll_id is unallocated\n");
    ret = -1;
    goto exit;
  }

  /*
   * 1. Fetch enroll:request command length and allocate memory
   */
  const atcommons_enroll_operation_t e_op = atcommons_apkam_request;
  size_t cmd_len = 0;
  atcommons_build_enroll_command(NULL, 0, &cmd_len, e_op, ep); // fetch enroll_command length
  const size_t cmd_size = cmd_len;
  char *command = malloc(sizeof(char) * cmd_size);
  if (command == NULL) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "Memory allocation failed for command\n");
    ret = -1;
    goto exit;
  }
  memset(command, 0, cmd_size);

  /*
   * 2. Build enroll:request command
   */
  if ((ret = atcommons_build_enroll_command(command, cmd_size, &cmd_len, e_op, ep)) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "Could not build enroll:request command\n");
    ret = -1;
    goto free_command_exit;
  }
  if (cmd_len >= cmd_size) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "buffer overflow in enroll command buffer");
    ret = -1;
    goto free_command_exit;
  }

  /*
   * 3. Send enroll:request command to server
   */
  if ((ret = atclient_connection_send(&client->atserver_connection, (const unsigned char *)command, cmd_len, recv,
                                      recv_size, &recv_len)) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atclient_connection_send: %d\n", ret);
    ret = 1;
    goto free_command_exit;
  }

  /*
   * 4. Trim + json-decode + read enrollment-id and enrollment status from the server response
   */
  if ((ret = atclient_string_utils_get_substring_position((const char *)recv, ATCLIENT_DATA_TOKEN, &recv_trimmed)) !=
      0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_DEBUG, "recv did not have prefix \"data:\"\n", (int)recv_len, recv);
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "%s\n", recv); // log error from server
    goto free_command_exit;
  }
  recv_trimmed += strlen(ATCLIENT_DATA_TOKEN);
  recv_trimmed[recv_len - strlen(ATCLIENT_DATA_TOKEN)] = '\0';

  cJSON *recv_json_decoded = cJSON_ParseWithLength(recv_trimmed, recv_len - strlen(ATCLIENT_DATA_TOKEN));
  if (recv_json_decoded == NULL) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "Failed to parse JSON response");
    ret = 1;
    goto cjson_delete_exit;
  }

  // parse and populate the enrollment id from server response
  const cJSON *enroll_id_cjson = cJSON_GetObjectItemCaseSensitive(recv_json_decoded, "enrollmentId");
  if (!cJSON_IsString(enroll_id_cjson) || (enroll_id_cjson->valuestring == NULL)) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "Failed to extract enrollment_id\n");
    ret = 1;
    goto cjson_delete_exit;
  }
  strncpy(enroll_id, enroll_id_cjson->valuestring, strlen(enroll_id_cjson->valuestring));
  enroll_id[strlen(enroll_id_cjson->valuestring)] = '\0';

  // parse and populate enrollment status from server response
  const cJSON *enroll_status_cjson = cJSON_GetObjectItemCaseSensitive(recv_json_decoded, "status");
  if (!cJSON_IsString(enroll_status_cjson) || (enroll_status_cjson->valuestring == NULL)) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "Failed to extract enroll status\n");
    ret = 1;
    goto cjson_delete_exit;
  }
  strncpy(enroll_status, enroll_status_cjson->valuestring, strlen(enroll_status_cjson->valuestring));
  enroll_status[strlen(enroll_status_cjson->valuestring)] = '\0';

  ret = 0;

cjson_delete_exit:
  cJSON_Delete(recv_json_decoded);
free_command_exit:
  free(command);
exit:
  return ret;
}
