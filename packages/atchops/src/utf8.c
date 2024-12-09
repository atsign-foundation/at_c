#include <atchops/platform.h>
#include <atchops/utf8.h>
#include <atlogger/atlogger.h>
#include <stddef.h>
#include <stdlib.h>
#include <wchar.h>

#define TAG "atchops-utf8"

int atchops_utf8_encode(const char *input, unsigned char **output, size_t *output_length) {
  int ret = 1;

  if (output_length == NULL || output == NULL || input == NULL) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "input, output or output_length is NULL\n");
    ret = -1;
    return ret;
  }

  // Get the length of the input string in wide characters
  const size_t len_wchar = mbstowcs(NULL, input, 0);
  if (len_wchar == (size_t)-1) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "invalid wide char length\n");
    ret = 1;
    return ret;
  }

  // Allocate memory for the wide character string
  wchar_t *wstr = malloc((len_wchar + 1) * sizeof(wchar_t));
  if (wstr == NULL) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "unable to allocate memory for wstr\n");
    ret = 2;
    return ret;
  }

  // Convert to wide characters
  mbstowcs(wstr, input, len_wchar + 1);

  // Calculate the size needed for UTF-8 encoding
  *output_length = wcslen(wstr) * 4; // UTF-8 can use up to 4 bytes per character
  *output = malloc(*output_length * sizeof(wchar_t));
  if (*output == NULL) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "unable to allocate memory for utf8_encode output\n");
    ret = 3;
    goto exit;
  }

  // Convert the wide character string to UTF-8
  *output_length = wcstombs((char *)*output, wstr, *output_length);
  if (*output_length == (size_t)-1) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "invalid utf8 output string length\n");
    ret = 4;
    free(*output);
    goto exit;
  }

  ret = 0;
exit: {
  free(wstr);
  return ret;
}
}
