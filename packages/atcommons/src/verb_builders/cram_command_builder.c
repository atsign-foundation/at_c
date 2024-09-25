#include "atcommons/cram_command_builder.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define CRAM_PREFIX "cram:"

int build_cram_command(char *command, unsigned char *digest) {
    int ret = 0;
    if(command == NULL) {
        ret = -1;
        goto exit;
    }

    size_t cmd_len = strlen(CRAM_PREFIX) + strlen((char*) digest);
    snprintf(command, cmd_len, "%s:%s\n", CRAM_PREFIX, digest);

    exit: { return ret; }
}