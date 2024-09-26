#include "atcommons/enroll_operation.h"
#include "atcommons/enroll_params.h"
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define TAG "enroll_verb_builder"
#define ENROLL_PREFIX "enroll:"
#define ENROLL_COMMAND_MAX_LENGTH 1500

int enroll_verb_build_command(char *command, enum EnrollOperation operation, EnrollParams *params) {
  int ret = 0;
  if (command == NULL) {
    ret = -1;
    goto exit;
  }

  // Write the enroll prefix into command
  memset(command, 0, ENROLL_COMMAND_MAX_LENGTH);
  int cur_len = 0;
  cur_len += snprintf(command, ENROLL_COMMAND_MAX_LENGTH, ENROLL_PREFIX);

  // Convert enroll operation to string, then write to command
  char *e_op;
  if ((ret = enroll_operation_to_string(&e_op, operation)) != 0) {
    goto exit;
  }
  cur_len += snprintf(command + cur_len, ENROLL_COMMAND_MAX_LENGTH, "%s:", e_op);

  // Convert enroll params to JSON, then append to command
  char *params_json;
  if ((ret = enroll_params_to_json(&params_json, params)) != 0) {
    goto exit;
  }
  cur_len += snprintf(command + cur_len, ENROLL_COMMAND_MAX_LENGTH, "%s", params_json);
  snprintf(command + cur_len, ENROLL_COMMAND_MAX_LENGTH, "\n"); //note that \n has been appended

  exit:
      return ret;
}
