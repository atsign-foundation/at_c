#ifndef ENROLL_VERB_BUILDER_H
#define ENROLL_VERB_BUILDER_H

#define MAX_COMMAND_LENGTH 1500

int enroll_verb_build_command(char *command, enum EnrollOperation operation, EnrollParams *params);

#endif
