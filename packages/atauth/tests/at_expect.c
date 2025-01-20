#include <stdio.h>
#include <string.h>
/*
 * Not a test. This is a test utility to compare expected and actual strings
 */
int atcommons_string_expect(char *actual, char *expected) {
  int ret = strcmp(actual, expected);
  if (ret != 0) {
    printf("test failed | ret: %d\nexpected: %s\n*actual*: %s\n", ret, expected, actual);
    printf("expected_len: %lu \t actual_len: %lu", strlen(expected), strlen(actual));
  }

  return ret;
}