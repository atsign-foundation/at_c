#ifndef ATCLIENT_ATLOGGER_H
#define ATCLIENT_ATLOGGER_H

#include <stddef.h>

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
void atlogger_log(const char *tag, const enum atlogger_logging_level level, const char *format, ...);
void atlogger_fix_stdout_buffer(char *str, const size_t strlen);

#endif
