#ifndef ENROLL_VERB_BUILDER_H
#define ENROLL_VERB_BUILDER_H

#define ENROLL_COMMAND_MAX_LENGTH 1500
#include "enroll_operation.h"
#include "enroll_params.h"
#include <stddef.h>

int atcommons_build_enroll_command(char *command, size_t *cmd_len, size_t cmd_size, enroll_operation_t operation,
                                   const enroll_params *params);

#endif
