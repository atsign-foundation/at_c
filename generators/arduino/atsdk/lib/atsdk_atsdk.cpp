// For both development and compile time
#include "atsdk.h"
#include <cstdarg>
#include <cstdio>
#include <cstdlib>

#ifdef __clang__ // For development to supress irrelevant errors
#include "../../../../packages/atlogger/include/atlogger/atlogger.h"
class DummySerial {
public:
  void print(const char *);
  void println(const char *);
};
extern DummySerial Serial;

#else // Actual compile time includes
#include <Arduino.h>
#endif

void atsdk_arduino_setup() {}

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
  int len = vsnprintf(NULL, 0, format, args);
  char *buf = new char[len + 1];
  vsnprintf(buf, len, format, args);
  Serial.println(buf);
  delete[] buf;

  va_end(args);
}
}
