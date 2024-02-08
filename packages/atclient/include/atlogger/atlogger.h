
#ifndef ATCLIENT_ATLOGGER_H
#define ATCLIENT_ATLOGGER_H

typedef enum atclient_atlogger_logging_level
{
    ATLOGGER_LOGGING_LEVEL_NONE = 0,   // literally nothing, not verbose at all
    ATLOGGER_LOGGING_LEVEL_ERROR,      // only errors, not that verbose
    ATLOGGER_LOGGING_LEVEL_WARN,    // errors and warnings , verbose only when something's up
    ATLOGGER_LOGGING_LEVEL_INFO,       // errors, warnings and info, pretty verbose
    ATLOGGER_LOGGING_LEVEL_DEBUG       // everything, very verbose
} atclient_atlogger_logging_level;

atclient_atlogger_logging_level atlogger_get_logging_level();
void atclient_atlogger_set_logging_level(atclient_atlogger_logging_level level);
void atclient_atlogger_log(const char *tag, atclient_atlogger_logging_level level, const char *format, ...);

#endif
