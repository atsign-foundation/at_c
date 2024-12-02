#include "atchops/hex.h"

#include <atlogger/atlogger.h>
#include <locale.h>
#include <stdio.h>
#include <stdlib.h>

#define TAG "atchops-hex"

int atchops_hex_to_bytes(unsigned char *bytes, const size_t byte_len, const char *hex_str) {
  int ret = 0;
  if (hex_str == NULL || bytes == NULL || byte_len <= 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "hex_string, bytes or byte_len is NULL\n");
    ret = -1;
    return ret;
  }

  for (size_t i = 0; i < byte_len; i++) {
    if (sscanf(hex_str + (i * 2U), "%2hhx", &bytes[i]) != 1) {
      atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "Error in hex_to_bytes conversion\n");
      ret = 1;
      return ret;
    }
  }

  return ret;
}

int atchops_bytes_to_hex(char *hex_str, const size_t hex_str_len, const unsigned char *bytes, const size_t bytes_len) {
  // Ensure the hex string buffer is large enough: 2 chars for each byte + 1 for null terminator
  if (hex_str_len < (bytes_len * 2 + 1)) {
      atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "Insufficient space for hex string\n");
    return -1;
  }

  for (size_t i = 0; i < bytes_len; i++) {
    snprintf(hex_str + i * 2, hex_str_len - i * 2, "%02x", bytes[i]);
  }

  hex_str[bytes_len * 2] = '\0';
  return 0;
}