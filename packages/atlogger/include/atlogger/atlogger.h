#ifndef ATCLIENT_ATLOGGER_H
#define ATCLIENT_ATLOGGER_H
#ifdef __cplusplus
extern "C" {
#endif

#include <stddef.h>
#include <stdio.h>

enum atlogger_logging_level {
  ATLOGGER_LOGGING_LEVEL_NONE = 0,   // literally nothing, not verbose at all
  ATLOGGER_LOGGING_LEVEL_ERROR = 10, // only errors, not that verbose
  ATLOGGER_LOGGING_LEVEL_WARN = 20,  // errors and warnings , verbose only when something's up
  // TODO: add FINE / FINER
  ATLOGGER_LOGGING_LEVEL_INFO = 50,   // errors, warnings and info, pretty verbose
  ATLOGGER_LOGGING_LEVEL_DEBUG = 100, // everything, very verbose
};

enum atlogger_logging_level atlogger_get_logging_level();
void atlogger_set_logging_level(const enum atlogger_logging_level level);
void atlogger_set_logging_stream(FILE *);
void atlogger_set_opts(int opts);
void atlogger_log(const char *tag, const enum atlogger_logging_level level, const char *format, ...);
void atlogger_fix_stdout_buffer(char *str, const size_t strlen);

typedef struct atlogger_ctx {
  enum atlogger_logging_level level;
  int opts;
} atlogger_ctx;

atlogger_ctx *atlogger_get_instance();
extern FILE *atlogger_logging_stream;

#ifndef ATLOGGER_OVERRIDE_LOG_FUNCTION
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#define PREFIX_BUFFER_LEN 64
void atlogger_get_prefix(enum atlogger_logging_level logging_level, char *prefix, size_t prefixlen);
void _atlogger_log(const char *tag, enum atlogger_logging_level level, const char *format, ...);

#if defined(ATSDK_DEBUG_MODE)
#define atlogger_log(TAG, LEVEL, FORMAT, ...)                                                                          \
  {                                                                                                                    \
    atlogger_ctx *ctx = atlogger_get_instance();                                                                       \
    if (LEVEL <= ctx->level) {                                                                                         \
      if (TAG != NULL) {                                                                                               \
        char *prefix = malloc(sizeof(char) * PREFIX_BUFFER_LEN);                                                       \
        if (prefix != NULL) {                                                                                          \
          atlogger_get_prefix(LEVEL, prefix, PREFIX_BUFFER_LEN);                                                       \
          fprintf(atlogger_logging_stream, "%.*s ", (int)strlen(prefix), prefix);                                      \
          fprintf(atlogger_logging_stream, "%s:%d - ", __FILE__, __LINE__);                                            \
          fprintf(atlogger_logging_stream, "%.*s | ", (int)strlen(TAG), TAG);                                          \
          free(prefix);                                                                                                \
        }                                                                                                              \
      }                                                                                                                \
    }                                                                                                                  \
    fprintf(atlogger_logging_stream, FORMAT __VA_OPT__(, ) __VA_ARGS__);                                               \
  }
#else
#define atlogger_log(TAG, LEVEL, FORMAT, ...) _atlogger_log(TAG, LEVEL, FORMAT __VA_OPT__(, ) __VA_ARGS__);
#endif
#endif

#ifdef __cplusplus
}
#endif
#endif
