#include "atclient/stringutils.h"
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>

int atclient_stringutils_trim_whitespace(const char *string, const size_t stringlen, char *out, const size_t outsize,
                                         size_t *outlen) {
  int ret = 1;

  if (string == NULL) {
    ret = 1;
    goto exit;
  }

  if (stringlen == 0) {
    ret = 1;
    goto exit;
  }

  // remove whitespace newlinetrailing/leading
  const char *start = string;
  while (*start && (*start == ' ' || *start == '\t' || *start == '\n')) {
    start++;
  }

  const char *end = string + stringlen - 1;
  while (end > start && (*end == ' ' || *end == '\t' || *end == '\n')) {
    end--;
  }

  *outlen = end - start + 1;

  if (*outlen >= outsize) {
    ret = 1;
    goto exit;
  }

  strncpy(out, start, *outlen);
  out[*outlen] = '\0';

  ret = 0;
  goto exit;
exit: { return ret; }
}

bool atclient_stringutils_starts_with(const char *string, const char *prefix) {
  return strncmp(string, prefix, strlen(prefix)) == 0;
}

bool atclient_stringutils_ends_with(const char *string, const char *suffix) {
  const size_t string_len = strlen(string);
  const size_t suffix_len = strlen(suffix);
  if (suffix_len > string_len) {
    return false;
  }
  return strncmp(string + string_len - suffix_len, suffix, suffix_len) == 0;

}

int atclient_stringutils_atsign_with_at(const char *original_atsign, char **output_atsign_with_at_symbol) {
  int ret = -1;
  if (original_atsign == NULL) {
    ret = -1;
    goto exit;
  }
  const size_t original_atsign_len = strlen(original_atsign);
  if (original_atsign_len == 0) {
    ret = -1;
    goto exit;
  }
  if (output_atsign_with_at_symbol == NULL) {
    ret = -1;
    goto exit;
  }

  if (original_atsign[0] == '@') {
    *output_atsign_with_at_symbol = malloc(sizeof(char) * (original_atsign_len + 1));
    if (*output_atsign_with_at_symbol == NULL) {
      ret = -1;
      goto exit;
    }
    memcpy(*output_atsign_with_at_symbol, original_atsign, original_atsign_len);
    (*output_atsign_with_at_symbol)[original_atsign_len] = '\0';
  } else {
    *output_atsign_with_at_symbol = malloc(sizeof(char) * (original_atsign_len + 2));
    if (*output_atsign_with_at_symbol == NULL) {
      ret = -1;
      goto exit;
    }
    memset(*output_atsign_with_at_symbol, 0, sizeof(char) * (original_atsign_len + 2));
    memcpy(*output_atsign_with_at_symbol, "@", 1);
    memcpy(*output_atsign_with_at_symbol + 1, original_atsign, original_atsign_len);
    (*output_atsign_with_at_symbol)[original_atsign_len + 1] = '\0';
  }

  ret = 0;
  goto exit;
exit: { return ret; }
}

int atclient_stringutils_atsign_without_at(const char *original_atsign, char **output_atsign_without_at_symbol) {
  int ret = -1;
  if (original_atsign == NULL) {
    ret = -1;
    goto exit;
  }
  const size_t original_atsign_len = strlen(original_atsign);
  if (original_atsign_len == 0) {
    ret = -1;
    goto exit;
  }
  if (output_atsign_without_at_symbol == NULL) {
    ret = -1;
    goto exit;
  }

  *output_atsign_without_at_symbol = malloc(sizeof(char) * (original_atsign_len));
  if (*output_atsign_without_at_symbol == NULL) {
    ret = -1;
    goto exit;
  }

  memset(*output_atsign_without_at_symbol, 0, sizeof(char) * (original_atsign_len));
  memcpy(*output_atsign_without_at_symbol, original_atsign + 1, original_atsign_len - 1);

  ret = 0;
  goto exit;
exit: { return ret; }
}

int long_strlen(long n) {
  // could use log10 for this, but it's probably slower...
  size_t len = 0;

  if (n == 0) {
    return 1;
  }

  if (n < 0) {
    n *= -1;
    len++; // for the minus sign
  }

  for (long i = 1; i <= n; i *= 10) {
    len++;
  }

  return len;
}
