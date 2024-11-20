#ifndef ENROLL_VERB_BUILDER_H
#define ENROLL_VERB_BUILDER_H

#include "enroll_operation.h"
#include "enroll_params.h"
#include <stddef.h>

#define ENROLL_COMMAND_MAX_LENGTH 1500

/**
 * @brief Constructs an enroll command based on the args provided. Currently only supports enroll:request
 *
 * @param command A pointer to store the constructed enroll command. Should be allocated of size
 * ENROLL_COMMAND_MAX_LENGTH
 * @param cmd_size Size of the command buffer
 * @param cmd_len A pointer to populate the length of the enroll command written into the command buffer
 * @param operation Specifies the type of enroll operation (request/approve/deny/revoke/revoke/list/delete)
 * @param params A pointer to the enroll_params_t struct that holds the parameters for the current enrollment operations
 * @return 0 on success, non-zero indicating failure
 */
int atcommons_build_enroll_command(char *command, size_t cmd_size, size_t *cmd_len, enroll_operation_t operation,
                                   const enroll_params_t *params);

#endif
