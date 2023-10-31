
#ifndef ATCLIENT_ATLOGGER_H
#define ATCLIENT_ATLOGGER_H

typedef enum atlogger_logging_level
{
    ATLOGGER_LOGGING_LEVEL_NONE = 0,   // literally nothing, not verbose at all
    ATLOGGER_LOGGING_LEVEL_ERROR,      // only errors, not that verbose
    ATLOGGER_LOGGING_LEVEL_WARN,    // errors and warnings , verbose only when something's up
    ATLOGGER_LOGGING_LEVEL_INFO,       // errors, warnings and info, pretty verbose
    ATLOGGER_LOGGING_LEVEL_DEBUG       // everything, very verbose
} atlogger_logging_level;

atlogger_logging_level atlogger_get_logging_level();
void atlogger_set_logging_level(atlogger_logging_level level);
void atlogger_log(const char *tag, atlogger_logging_level level, const char *format, ...);

#endif
