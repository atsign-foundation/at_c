#include <atlogger/atlogger.h>

#define TAG "main"

int main() {
  int ret = 1;

  atlogger_set_logging_level(ATLOGGER_LOGGING_LEVEL_DEBUG);

  // Enter your code here

  ret = 0;

exit: { return ret; }
}