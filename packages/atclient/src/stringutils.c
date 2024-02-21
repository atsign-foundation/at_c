#include "atclient/stringutils.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int atclient_stringutils_trim_whitespace(const char *string, const unsigned long stringlen, char *out,
                                         const unsigned long outlen, unsigned long *outolen) {
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

  *outolen = end - start + 1;

  if (*outolen >= outlen) {
    ret = 1;
    goto exit;
  }

  strncpy(out, start, *outolen);
  out[*outolen] = '\0';

  ret = 0;
  goto exit;
exit: { return ret; }
}

int atclient_stringutils_starts_with(const char *string, const unsigned long stringlen, const char *prefix,
                                     const unsigned long prefixlen) {
  int ret = -1;
  if (string == NULL || prefix == NULL) {
    ret = -1;
    goto exit;
  }

  if (stringlen == 0 || prefixlen == 0) {
    ret = -1;
    goto exit;
  }

  if (stringlen < prefixlen) {
    ret = -1;
    goto exit;
  }

  ret = strncmp(string, prefix, strlen(prefix));
  if (ret == 0) {
    ret = 1; // true
  } else if (ret != 0) {
    ret = 0; // false
  }

  goto exit;
exit: { return ret; }
}

int atclient_stringutils_ends_with(const char *string, const unsigned long stringlen, const char *suffix,
                                   const unsigned long suffixlen) {
  int ret = -1;
  if (string == NULL || suffix == NULL) {
    ret = -1;
    goto exit;
  }
  if (stringlen == 0 || suffixlen == 0) {
    ret = -1;
    goto exit;
  }
  if (stringlen < suffixlen) {
    ret = -1;
    goto exit;
  }
  ret = strncmp(string + stringlen - suffixlen, suffix, suffixlen);
  if (ret == 0) {
    ret = 1; // true
  } else if (ret != 0) {
    ret = 0; // false
  }

  goto exit;
exit: { return ret; }
}
