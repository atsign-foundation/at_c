#ifndef CRAM_COMMAND_BUILDER_H
#define CRAM_COMMAND_BUILDER_H
#include <stddef.h>

int atcommons_build_cram_command(char **cmd, size_t *cmd_len, size_t cmd_buffer_size, const char *digest, size_t digest_len);

#endif //CRAM_COMMAND_BUILDER_H
