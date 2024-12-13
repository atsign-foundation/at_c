#include "./atsdk_atlogger.h"
#include <cstdio>

extern "C" {
void atlogger_log(const char *tag, const enum atlogger_logging_level level, const char *format, ...) {
  atlogger_logging_level allowed_level = atlogger_get_logging_level();
  if (level > allowed_level) {
    return;
  }

  va_list args;
  va_start(args, format);
  if (tag != nullptr) {
    Serial.print(tag);
    Serial.print(" | ");
  }
  int len = vsnprintf(NULL, 0, format, args) + 1;
  char *buf = new char[len];
  vsnprintf(buf, len, format, args);
  for (int i = 0; i < len; i++) {
    if (*(buf + i) == '\n') {
      Serial.println();
    } else {
      Serial.print(*(buf + i));
    }
  }
  delete[] buf;

  va_end(args);
}
}
