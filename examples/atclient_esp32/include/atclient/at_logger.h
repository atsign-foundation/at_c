#ifndef ATLOGGER_H
#define ATLOGGER_H

#include <stddef.h>

int atlogger_log(const char *title, const char *message);
int atlogger_logx(const char *title, const unsigned char *bytes, size_t byteslen);

#endif  // ATLOGGER_H
