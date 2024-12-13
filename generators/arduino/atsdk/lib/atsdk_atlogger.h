// For both development and compile time
#include <cstdarg>
#include <cstdlib>

#ifdef __clang__ // For development to supress irrelevant errors
// Include the relative atlogger header when in development mode
#include "../../../../packages/atlogger/include/atlogger/atlogger.h" // IWYU pragma: export
class DummySerial {
public:
  void print(const char *);
  void print(const char);
  void println();
};
extern DummySerial Serial; // Tricks clangd, since clangd can't find Serial class

#else // Actual compile time includes
#include "atsdk.h"
#include <Arduino.h>
#endif
