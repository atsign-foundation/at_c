#ifndef ATCLIENT_ATLOGGER_H
#define ATCLIENT_ATLOGGER_H

#define INFO_PREFIX "\e[0;32m[INFO]\e[0m"
#define WARN_PREFIX "\e[0;31m[WARN]\e[0m"
#define ERROR_PREFIX "\e[1;31m[ERRO]\e[0m"
#define DEBUG_PREFIX "\e[0;34m[DEBG]\e[0m"

enum atlogger_logging_level {
  ATLOGGER_LOGGING_LEVEL_NONE = 0,   // literally nothing, not verbose at all
  ATLOGGER_LOGGING_LEVEL_ERROR = 10, // only errors, not that verbose
  ATLOGGER_LOGGING_LEVEL_WARN = 20,  // errors and warnings , verbose only when something's up
  // TODO: add FINE / FINER
  ATLOGGER_LOGGING_LEVEL_INFO = 50,   // errors, warnings and info, pretty verbose
  ATLOGGER_LOGGING_LEVEL_DEBUG = 100, // everything, very verbose
};

static const char *atlogger_logging_level_str[] = {
    [ATLOGGER_LOGGING_LEVEL_NONE] = "",
    [ATLOGGER_LOGGING_LEVEL_ERROR] = ERROR_PREFIX,
    [ATLOGGER_LOGGING_LEVEL_WARN] = WARN_PREFIX,
    [ATLOGGER_LOGGING_LEVEL_INFO] = INFO_PREFIX,
    [ATLOGGER_LOGGING_LEVEL_DEBUG] = DEBUG_PREFIX,
};

void atlogger_set_logging_level(const enum atlogger_logging_level level);
void atlogger_log(const char *tag, const enum atlogger_logging_level level, const char *format, ...);

#endif
