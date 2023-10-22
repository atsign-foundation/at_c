
#ifndef ATLOGGER_H
#define ATLOGGER_H

typedef enum atlogger_logging_level
{
    ATLOGGER_LOGGING_LEVEL_NONE = 0,   // literally nothing
    ATLOGGER_LOGGING_LEVEL_ERROR,      // only errors
    ATLOGGER_LOGGING_LEVEL_WARNING,    // errors and warnings
    ATLOGGER_LOGGING_LEVEL_INFO,       // errors, warnings and info
    ATLOGGER_LOGGING_LEVEL_DEBUG       // everything
} atlogger_logging_level;

atlogger_logging_level atlogger_get_logging_level();
void atlogger_set_logging_level(atlogger_logging_level level);
void atlogger_log(atlogger_logging_level level, const char *format, ...);

#endif
