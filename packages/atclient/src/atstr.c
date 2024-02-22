#include "atclient/atstr.h"
#include "atlogger/atlogger.h"
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define TAG "atstr"

void atclient_atstr_init(atclient_atstr *atstr, const unsigned long bufferlen) {
  memset(atstr, 0, sizeof(atclient_atstr));
  atstr->len = bufferlen;
  atstr->str = (char *)malloc(sizeof(char) * atstr->len);
  memset(atstr->str, 0, sizeof(char) * atstr->len);
  atstr->olen = 0;
}

int atclient_atstr_init_literal(atclient_atstr *atstr, const unsigned long bufferlen, const char *format, ...) {
  int ret = 1;
  atclient_atstr_init(atstr, bufferlen);
  ret = atclient_atstr_set_literal(atstr, format);
  if (ret != 0) {
    atclient_atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atclient_atstr_set_literal failed");
    goto exit;
  }
  goto exit;
exit: { return ret; }
}

void atclient_atstr_reset(atclient_atstr *atstr) {
  memset(atstr->str, 0, atstr->len);
  atstr->olen = 0;
}

int atclient_atstr_set_literal(atclient_atstr *atstr, const char *format, ...) {
  int ret = 1;
  if (atstr->str == NULL) {
    atclient_atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atstr->str is NULL\n");
    goto exit;
  }
  va_list args;
  va_start(args, format);
  ret = vsnprintf(atstr->str, atstr->len, format, args);
  va_end(args); // Add va_end() to properly handle variadic arguments
  if (ret < 0) {
    atclient_atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "vsnprintf failed");
    goto exit;
  }
  atstr->olen = ret;
  ret = 0;
  goto exit;
exit: { return ret; }
}

int atclient_atstr_set(atclient_atstr *atstr, const char *str, const unsigned long len) {
  int ret = 1;

  if (len > atstr->len) {
    ret = 1;
    atclient_atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "len > atstr->len (%d > %d)\n", len, atstr->len);
    goto exit;
  }

  memcpy(atstr->str, str, len);
  atstr->olen = len;

  ret = 0;
  goto exit;

exit: { return ret; }
}

int atclient_atstr_copy(atclient_atstr *atstr, atclient_atstr *data) {
  int ret = 1;
  ret = atclient_atstr_set(atstr, data->str, data->olen);
  if (ret != 0) {
    atclient_atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atclient_atstr_set failed");
    goto exit;
  }
  goto exit;
exit: { return ret; }
}

int atclient_atstr_substring(atclient_atstr *substring, const atclient_atstr original, const unsigned long start,
                             const unsigned long end) {
  int ret = 1;
  if (start > original.olen || end > original.olen) {
    atclient_atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "start or end is greater than original.olen\n");
    goto exit;
  }
  if (start > end) {
    atclient_atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "start is greater than end\n");
    goto exit;
  }
  if (end - start > substring->len) {
    atclient_atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "end - start > substring->len\n");
    goto exit;
  }
  memcpy(substring->str, original.str + start, end - start);
  substring->olen = end - start;
  ret = 0;
  goto exit;

exit: { return ret; }
}

int atclient_atstr_append(atclient_atstr *atstr, const char *format, ...) {
  int ret = 1;
  va_list args;
  va_start(args, format);
  ret = vsnprintf(atstr->str + atstr->olen, atstr->len - atstr->olen, format, args);
  if (ret < 0) {
    atclient_atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "vsnprintf failed");
    goto exit;
  }
  atstr->olen += ret;
  ret = 0;
  goto exit;
exit: { return ret; }
}

void atclient_atstr_free(atclient_atstr *atstr) { free(atstr->str); }
