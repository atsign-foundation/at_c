#include "atchops/hex_utils.h"

#include <locale.h>
#include <stdio.h>
#include <stdlib.h>
#include <wchar.h>

int atchops_hex_to_bytes(const char *hex, unsigned char *bytes, size_t byte_len) {
  int ret = 0;
  if (hex == NULL || bytes == NULL || byte_len <= 0) {
    ret = -1;
    return ret;
  }

  for (size_t i = 0; i < byte_len; i++) {
    if (sscanf(hex + (i * 2), "%2hhx", &bytes[i]) != 1) {
      ret = -1; // Error in conversion
      return ret;
    }
  }

  return ret;
}

int atchops_bytes_to_hex_string(const unsigned char *input, size_t len, char *output) {
  int ret = 0;
  if (input == NULL || output == NULL || len <= 0) {
    ret = -1;
    return ret;
  }

  // Iterate over each byte in the input array
  for (size_t i = 0; i < len; i++) {
    // Convert each unsigned char to a 2-character hex string and append it to the output
    sprintf(output + (i * 2), "%02x", input[i]);
  }
  output[len * 2] = '\0'; // Null-terminate the string

  return ret;
}

int atchops_utf8_encode(const char *input, unsigned char **output, size_t *output_length) {
  int ret = 1;

  if (output_length == NULL || output == NULL || input == NULL) {
    return ret;
  }

  // Get the length of the input string in wide characters
  size_t len_wchar = mbstowcs(NULL, input, 0);
  if (len_wchar == (size_t)-1) {
    return ret;
  }

  // Allocate memory for the wide character string
  wchar_t *wstr = malloc((len_wchar + 1) * sizeof(wchar_t));
  if (wstr == NULL) {
    return ret;
  }

  // Convert to wide characters
  mbstowcs(wstr, input, len_wchar + 1);

  // Calculate the size needed for UTF-8 encoding
  *output_length = wcslen(wstr) * 4; // UTF-8 can use up to 4 bytes per character
  *output = malloc(*output_length);
  if (*output == NULL) {
    goto exit;
  }

  // Convert the wide character string to UTF-8
  *output_length = wcstombs((char *)*output, wstr, *output_length);
  if (*output_length == (size_t)-1) {
    free(*output);
    goto exit;
  }

  ret = 0;
exit: {
  free(wstr);
  return ret;
}
}
