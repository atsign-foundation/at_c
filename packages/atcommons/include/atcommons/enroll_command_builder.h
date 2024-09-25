#ifndef ENROLL_VERB_BUILDER_H
#define ENROLL_VERB_BUILDER_H

#define ENROLL_COMMAND_MAX_LENGTH 1500

int build_enroll_command(char *command, const enum ENROLL_OPERATION operation, const enroll_params *params);

#endif
