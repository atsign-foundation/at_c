// For both development and compile time
#include <cstdarg>
#include <cstdio>
#include <cstdlib>

#ifdef __clang__ // For development to supress irrelevant errors
// Include the relative atlogger header when in development mode
#include "../../../../packages/atlogger/include/atlogger/atlogger.h" // IWYU pragma: export
class DummySerial {
public:
  void print(const char *);
  void print(const char);
  void println();
  void println(const char *);
};
extern DummySerial Serial; // Tricks clangd, since clangd can't find Serial class

#else // Actual compile time includes
#include "atsdk.h"
#include <Arduino.h>
#endif

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
