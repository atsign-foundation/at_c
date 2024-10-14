#include "atauth/send_enroll_request.h"

#include "atclient/atclient.h"
#include "atcommons/enroll_command_builder.h"
#include "atcommons/enroll_params.h"
#include "atlogger/atlogger.h"
#include "atclient/constants.h"
#include "atclient/string_utils.h"
#include "atcommons/enroll_operation.h"
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>

int atauth_send_enroll_request(char *enroll_id, atclient *client, enroll_params *ep) {
  int ret = 0;
  size_t recv_size = 100; // to hold the response for enroll request
  char recv[recv_size];
  char *recv_trimmed = NULL;
  size_t recv_len;

  /*
   * 1. Fetch enroll:request command length and allocate memory
   */
  enroll_operation_t e_op = REQUEST;
  size_t cmd_len = 0, cmd_size = 0;
  printf("command len is %lu\n", cmd_len);
  atcommons_build_enroll_command(NULL, &cmd_len, NULL, e_op, ep); // fetch enroll_command length
  cmd_size = cmd_len + 1;
  atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_INFO, "fetched enroll commmand length: %lu\n", cmd_len);
  char *command = malloc(sizeof(char) * cmd_size); // +1 for the null-terminator
  memset(command, 0, sizeof(char) * cmd_size );
  if (command == NULL) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "Memory allocation failed for command\n");
    ret = -1;
    goto exit;
  }
  /*
   * 2. Build enroll:request command
   */
  if ((ret = atcommons_build_enroll_command(command, &cmd_len, cmd_size, e_op, ep)) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "Could not build enroll:request command\n");
    ret = -1;
    goto exit;
  }
  if(cmd_len > cmd_size) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "buffer overflow in enroll command buffer");
    ret = -1;
    goto exit;
  }
  printf("enroll command: %s\n", command);

  /*
   * 3. Send enroll:request command to server
   */
  if ((ret = atclient_connection_send(&(client->atserver_connection), command, cmd_len, recv, recv_size, &recv_len)) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atclient_connection_send: %d\n", ret);
    ret = 1;
    goto exit;
  }

  /*
   * 4. Trim + json-decode + read enrollment-id from the server response
   */
  // below method points to the position of 'data:' substring
  if (atclient_string_utils_get_substring_position(recv, DATA_TOKEN, &recv_trimmed) != 0) {
    ret = 1;
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "recv was \"%.*s\" and did not have prefix \"data:\"\n",
                 (int)recv_len, recv);
    goto exit;
  }
  recv_trimmed = recv_trimmed + strlen(DATA_TOKEN);
  atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_INFO, "recv: %s\n", recv_trimmed);

  cJSON *recv_json_decoded = cJSON_ParseWithLength(recv_trimmed, recv_len - strlen(DATA_TOKEN));
  // populate the enrollment id from response
  cJSON *enroll_id_cjson = cJSON_GetObjectItemCaseSensitive(recv_json_decoded, "enrollmentId");
  if (cJSON_IsString(enroll_id_cjson) && (enroll_id_cjson->valuestring != NULL)) {
    strcpy(enroll_id, enroll_id_cjson);
  }

exit: { return ret; }
}