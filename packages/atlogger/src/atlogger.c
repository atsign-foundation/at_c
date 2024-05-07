
#include "atlogger/atlogger.h"
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stddef.h>

typedef struct atlogger_ctx {
  enum atlogger_logging_level level;
} atlogger_ctx;

static atlogger_ctx *atlogger_get_instance() {
  static atlogger_ctx *ctx;

  if (ctx == NULL) {
    ctx = (atlogger_ctx *)malloc(sizeof(atlogger_ctx));
  }

  return ctx;
}

enum atlogger_logging_level atlogger_get_logging_level() {
  atlogger_ctx *ctx = atlogger_get_instance();
  return ctx->level;
}

void atlogger_set_logging_level(const enum atlogger_logging_level level) {
  atlogger_ctx *ctx = atlogger_get_instance();
  ctx->level = level;
}

void atlogger_log(const char *tag, const enum atlogger_logging_level level, const char *format, ...) {
  // atlogger_ctx *ctx = atlogger_get_instance();

  // if (level > ctx->level) {
  //   return;
  // }

  // atlogger_get_prefix(level, prefix, PREFIX_BUFFER_LEN);

  va_list args;
  va_start(args, format);
  printf(" %.*s", (int)strlen(atlogger_logging_level_str[level]), atlogger_logging_level_str[level]);
  if (tag != NULL) {
    printf("\t%s", tag);
  }
  printf(" | ");
  vprintf(format, args);
  va_end(args);
}
