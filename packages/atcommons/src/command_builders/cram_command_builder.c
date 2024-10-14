#include "atcommons/cram_command_builder.h"

#include <atlogger/atlogger.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define CRAM_PREFIX "cram"
#define TAG "cram_command_builder"

int atcommons_build_cram_command(char **cmd, size_t *cmd_len, size_t cmd_buffer_size, const char *digest,
                                 size_t digest_len) {
  int ret = 0;

  if(digest == NULL || digest_len <=0) {
    ret = -1;
    goto exit;
  }
  if (cmd == NULL) {
    *cmd_len = snprintf(NULL, 0, "%s:%s\r\n", CRAM_PREFIX, digest);
    ret = 1;
    goto exit;
  }

  *cmd_len = snprintf(*cmd, sizeof(char) * *cmd_len, "%s:%s\r\n", CRAM_PREFIX, digest);
  atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_INFO, "cram_cmd_len: %lu | cram_cmd_size: %lu\n", *cmd_len, cmd_buffer_size);

  if(*cmd_len > cmd_buffer_size) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "Buffer overflow in atcommons_build_cram_command\n");
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_DEBUG, "cram_cmd_len: %lu | cram_cmd_size: %lu\n", cmd_len, cmd_buffer_size);
    ret = 1;
    goto exit;
  }

  exit:
      return ret;
}
