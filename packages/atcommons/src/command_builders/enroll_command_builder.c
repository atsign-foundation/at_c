#include "atcommons/enroll_command_builder.h"
#include "atcommons/enroll_operation.h"
#include "atcommons/enroll_params.h"
#include "atlogger/atlogger.h"

#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define ENROLL_PREFIX "enroll:"
#define TAG "enroll command builder"

int atcommons_build_enroll_command(char *command, const size_t cmd_size, size_t *cmd_len,
                                   const atcommons_enroll_operation_t operation, const atcommons_enroll_params_t *params) {
  int ret = 0;
  int cur_len = 0;
  char *params_json = NULL, *e_op = NULL;
  size_t params_json_len = 0;

  e_op = malloc(sizeof(char) * MAX_ENROLL_OPERATION_STRING_LEN);
  if (e_op == NULL) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "Could not allocate memory for enroll op string\n");
    ret = -1;
    goto free_params_json;
  }
  memset(e_op, 0, sizeof(char) * MAX_ENROLL_OPERATION_STRING_LEN);

  // A, B, C and D are used ONLY to calculate the expected command length
  if (command == NULL && cmd_size == 0) {
    /*
     * A. Caclculate enroll prefix len
     */
    cur_len += snprintf(NULL, 0, "%s", ENROLL_PREFIX);

    /*
     * B. Calculate enroll operation len
     */
    if ((ret = atcommons_enroll_operation_to_string(&e_op, operation)) != 0) {
      atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atcommons_atcommons_enroll_operation_to_string: %d\n", ret);
      goto free_enroll_op;
    }
    cur_len += snprintf(NULL, 0, "%s:", e_op);

    /*
     * C. Calculate enroll params json len
     */
    atcommons_enroll_params_to_json(NULL, &params_json_len, params); // fetch 'enroll_params_json' length
    cur_len += params_json_len + 3;                                  // +2 for \r\n\0

    /*
     * D. Populate 'cmd_len' with the calculated commmand length
     */
    *cmd_len = cur_len;
    ret = 1; // setting a non-zero exit code to ensure this if-clause is only used for commadn len calculation
    goto free_enroll_op;
  }

  /*
   * 1. Write the enroll prefix into command
   */
  cur_len += snprintf(command, cmd_size, "%s", ENROLL_PREFIX);

  /*
   * 2. Convert enroll operation to string, then append to command
   */
  if ((ret = atcommons_enroll_operation_to_string(&e_op, operation)) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atcommons_enroll_operation_to_string: %d\n", ret);
    ret = 1;
    return ret;
  }
  cur_len += snprintf(command + cur_len, cmd_size, "%s:", e_op);

  /*
   * 3. Convert enroll params to JSON, then append to command
   */
  if ((ret = atcommons_enroll_params_to_json(&params_json, &params_json_len, params)) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atcommons_enroll_params_to_json: %d\n", ret);
    goto exit;
  }

  // populate enroll_params_json into 'command'
  cur_len += snprintf(command + cur_len, cmd_size, "%s\r\n", params_json);
  *cmd_len = cur_len;

free_enroll_op: { free(e_op); }
free_params_json: { free(params_json); }
exit: { return ret; }
}
