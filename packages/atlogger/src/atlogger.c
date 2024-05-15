
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
  enum atlogger_logging_level level;
} atlogger_ctx;

static void atlogger_get_prefix(enum atlogger_logging_level logging_level, char *prefix,
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

enum atlogger_logging_level atlogger_get_logging_level() {
  atlogger_ctx *ctx = atlogger_get_instance();
  return ctx->level;
}

void atlogger_set_logging_level(const enum atlogger_logging_level level) {
  atlogger_ctx *ctx = atlogger_get_instance();
  ctx->level = level;
}

void atlogger_log(const char *tag, const enum atlogger_logging_level level, const char *format, ...) {
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

void atlogger_fix_stdout_buffer(char *str, const size_t strlen) {
  // if str == 'Jeremy\r\n', i want it to be 'Jeremy'
  // if str == 'Jeremy\n', i want it to be 'Jeremy'
  // if str == 'Jeremy\r', i want it to be 'Jeremy'

  if (strlen == 0) {
    goto exit;
  }

  int carriagereturnindex = -1;
  int newlineindex = -1;

  for (int i = strlen; i >= 0; i--) {
    if (str[i] == '\r' && carriagereturnindex == -1) {
      carriagereturnindex = i;
    }
    if (carriagereturnindex != -1 && newlineindex != -1) {
      break;
    }
  }

  if (carriagereturnindex != -1) {
    for (int i = carriagereturnindex; i < strlen - 1; i++) {
      str[i] = str[i + 1];
    }
    str[strlen - 1] = '\0';
  }

  for (int i = strlen; i >= 0; i--) {
    if (str[i] == '\n' && newlineindex == -1) {
      newlineindex = i;
    }
    if (carriagereturnindex != -1 && newlineindex != -1) {
      break;
    }
  }

  if (newlineindex != -1) {
    for (int i = newlineindex; i < strlen - 1; i++) {
      str[i] = str[i + 1];
    }
    str[strlen - 1] = '\0';
  }

  goto exit;

exit: { return; }
}
