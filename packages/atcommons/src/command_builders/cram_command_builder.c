#include "atcommons/cram_command_builder.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define CRAM_PREFIX "cram"

int atcommons_build_cram_command(char **cmd, size_t *cmd_len, const char *digest, size_t digest_len) {
  int ret = 0;
  *cmd_len = strlen(CRAM_PREFIX) + digest_len + strlen("\r\n") + 1;

  *cmd = malloc(sizeof(char) * *cmd_len);
  if (*cmd == NULL) {
    ret = -1;
    goto exit;
  }
  memset(*cmd, 0, sizeof(char) * *cmd_len);

  int len = snprintf(*cmd, sizeof(char) * *cmd_len, "%s:%s\r\n", CRAM_PREFIX, digest);

  if (len <= 0){ //|| (size_t)len >= *cmd_len) {
    ret = 1;
    printf("len: %d \ncmd_len: %lu\n", len, *cmd_len);
    free(*cmd);
    goto exit;
  }
  printf("cram command len: %d\n", len);

  exit:
      return ret;
}
