
#include "atlogger/atlogger.h"
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stddef.h>

#define PREFIX_BUFFER_LEN 64
#define INFO_PREFIX "\e[0;32m[INFO]\e[0m"
#define WARN_PREFIX "\e[0;31m[WARN]\e[0m"
#define ERROR_PREFIX "\e[1;31m[ERRO]\e[0m"
#define DEBUG_PREFIX "\e[0;34m[DEBG]\e[0m"

static char *prefix;

typedef struct atlogger_ctx {
  enum atclient_atlogger_logging_level level;
} atlogger_ctx;

static void atlogger_get_prefix(enum atclient_atlogger_logging_level logging_level, char *prefix,
                                size_t prefixlen) {
  memset(prefix, 0, prefixlen);
  switch (logging_level) {
  case ATLOGGER_LOGGING_LEVEL_INFO: {
    memcpy(prefix, INFO_PREFIX, strlen(INFO_PREFIX));
    break;
  }
  case ATLOGGER_LOGGING_LEVEL_WARN: {
    memcpy(prefix, WARN_PREFIX, strlen(WARN_PREFIX));
    break;
  }
  case ATLOGGER_LOGGING_LEVEL_ERROR: {
    memcpy(prefix, ERROR_PREFIX, strlen(ERROR_PREFIX));
    break;
  }
  case ATLOGGER_LOGGING_LEVEL_DEBUG: {
    memcpy(prefix, DEBUG_PREFIX, strlen(DEBUG_PREFIX));
    break;
  }
  default: {
    break;
  }
  }
}

static atlogger_ctx *atlogger_get_instance() {
  static atlogger_ctx *ctx;

  if (ctx == NULL) {
    ctx = (atlogger_ctx *)malloc(sizeof(atlogger_ctx));
    prefix = (char *)malloc(sizeof(char) * PREFIX_BUFFER_LEN);
    memset(prefix, 0, sizeof(char) * PREFIX_BUFFER_LEN);
  }

  return ctx;
}

enum atclient_atlogger_logging_level atlogger_get_logging_level() {
  atlogger_ctx *ctx = atlogger_get_instance();
  return ctx->level;
}

void atclient_atlogger_set_logging_level(const enum atclient_atlogger_logging_level level) {
  atlogger_ctx *ctx = atlogger_get_instance();
  ctx->level = level;
}

void atclient_atlogger_log(const char *tag, const enum atclient_atlogger_logging_level level, const char *format, ...) {
  atlogger_ctx *ctx = atlogger_get_instance();

  if (level > ctx->level) {
    return;
  }

  atlogger_get_prefix(level, prefix, PREFIX_BUFFER_LEN);

  va_list args;
  va_start(args, format);
  printf(" %.*s", (int)strlen(prefix), prefix);
  if (tag != NULL) {
    printf("\t%s", tag);
  }
  printf(" | ");
  vprintf(format, args);
  va_end(args);
}
