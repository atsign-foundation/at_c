#include <stdio.h>
#include <string.h>
#include "atcommons/at_expect.h"

int atcommons_string_expect(char *actual, char*expected){
  int ret = strcmp(actual, expected);
  if (ret != 0) {
    printf("test failed\nexpected: %s\n*actual*: %s\n", expected, actual);
  }

  return ret;
}