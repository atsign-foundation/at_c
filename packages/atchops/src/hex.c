#include "atchops/hex.h"

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

int atchops_bytes_to_hex(char *hex_str, size_t hex_str_len, const unsigned char *bytes, size_t byte_len) {
  // Ensure the hex string buffer is large enough: 2 chars for each byte + 1 for null terminator
  if (hex_str_len < (byte_len * 2 + 1)) {
    // Insufficient space for hex string
    return -1;
  }

  for (size_t i = 0; i < byte_len; i++) {
    // Use mbedTLS's safe snprintf function if available
    snprintf(hex_str + i * 2, hex_str_len - i * 2, "%02x", bytes[i]);
  }

  // Null-terminate the string
  hex_str[byte_len * 2] = '\0';
  return 0;
}