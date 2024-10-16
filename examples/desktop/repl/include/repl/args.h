#ifndef REPL_ARGS_H
#define REPL_ARGS_H

#include <stdint.h>

#define REPL_ARGS_ATSIGN_MANDATORY 1
#define REPL_ARGS_ROOT_URL_MANDATORY 0

#define REPL_ARGS_ROOT_URL_DEFAULT "root.atsign.org:64"

typedef struct repl_args {
    char *atsign;
    char *root_url;
    char *key_file;
} repl_args;

void repl_args_init(repl_args *args);
void repl_args_free(repl_args *args);

int repl_args_parse(repl_args *args, const int argc, const char *argv[]);

#endif