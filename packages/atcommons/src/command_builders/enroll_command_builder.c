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

// possible improvements: allocate mem and return a null-terminated string and its the callers responsibility to replace
// \0 with \n and free when done

int atcommons_build_enroll_command(char *command, size_t cmd_size, size_t *cmd_len, enroll_operation_t operation,
                                   const enroll_params_t *params) {
  int ret = 0;
  int cur_len = 0;
  char *params_json = NULL;
  size_t params_json_len = 0, params_json_size = 0;
  enroll_params_to_json(NULL, &params_json_len, NULL, params); // fetch length of params json string
  params_json_size = params_json_len + 1;                      // specify the size of the buffer
  params_json = malloc(sizeof(char) * params_json_size);       // to be freed 2
  memset(params_json, 0, sizeof(char) * params_json_size);

  if (command == NULL) {                             // Calculate the expected command length
    char *e_op = malloc(sizeof(enroll_operation_t)); // to be freed 1
    memset(e_op, 0, sizeof(enroll_operation_t));
    if (e_op == NULL) {
      atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "could not allocate memory for enroll_operation\n");
      ret = -1;
      return ret;
    }
    /*
     * 1. Caclculate enroll prefix len
     */
    cur_len += snprintf(NULL, 0, "%s", ENROLL_PREFIX);

    /*
     * 2. Calculate enroll operation len
     */
    if ((ret = enroll_operation_to_string(&e_op, operation)) != 0) {
      atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "enroll_operation_to_string: %d\n", ret);
      return ret;
    }
    cur_len += snprintf(NULL, 0, "%s:", e_op);

    /*
     * 3. Calculate enroll params json len
     */
    enroll_params_to_json(NULL, &params_json_len, NULL, params); // fetch 'enroll_params_json' length
    cur_len += (size_t)params_json_len + 3;                      // +2 for \r\n\0

    /*
     * 4. Populate 'cmd_len' with the calculated commmand length
     */
    *cmd_len = cur_len;
    free(e_op); // freed 1
    ret = 1;
    return ret;
  }

  /*
   * 1. Write the enroll prefix into command
   */
  cur_len += snprintf(command, cmd_size, "%s", ENROLL_PREFIX);

  /*
   * 2. Convert enroll operation to string, then append to command
   */
  char *e_op = malloc(MAX_ENROLL_OPERATION_STRING_LEN); // to be freed 1
  if ((ret = enroll_operation_to_string(&e_op, operation)) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "enroll_operation_to_string: %d\n", ret);
    ret = 1;
    return ret;
  }
  cur_len += snprintf(command + cur_len, cmd_size, "%s:", e_op);

  /*
   * 3. Convert enroll params to JSON, then append to command
   */
  if (params_json == NULL) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "Could not allocate mem for params_json\n");
    ret = -1;
    goto exit;
  }
  if ((ret = enroll_params_to_json(&params_json, &params_json_len, params_json_size, params)) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "enroll_params_to_json: %d\n", ret);
    ret = 1;
    goto exit;
  }
  if (params_json_len > params_json_size) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "buffer overflow in params_json\n");
    ret = -1;
    goto exit;
  }
  // populate enroll_params_json into 'command'
  cur_len += snprintf(command + cur_len, cmd_size, "%s\r\n", params_json);
  // command[cur_len] = '\n'; // note that \n has been appended
  *cmd_len = cur_len;
  
exit: {
  free(e_op);        // freed 1
  free(params_json); // freed 2
  return ret;
}
}
