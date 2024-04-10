#include "atclient/atbytes.h"
#include "atclient/atstr.h"
#include "atlogger/atlogger.h"
#include <stdlib.h>
#include <string.h>
#include <stddef.h>

#define TAG "atbytes"

void atclient_atbytes_init(atclient_atbytes *atbytes, const size_t atbyteslen) {
  memset(atbytes, 0, sizeof(atclient_atbytes));
  atbytes->len = atbyteslen;
  atbytes->bytes = malloc(sizeof(unsigned char) * atbytes->len);
  atbytes->olen = 0;
}

void atclient_atbytes_reset(atclient_atbytes *atbytes) {
  memset(atbytes->bytes, 0, sizeof(unsigned char) * atbytes->len);
  atbytes->olen = 0;
}

int atclient_atbytes_set(atclient_atbytes *atbytes, const unsigned char *bytes, const size_t byteslen) {
  int ret = 1;
  if (byteslen > atbytes->len) {
    atclient_atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR,
                          "byteslen is greater than atbyteslen. byteslen: %lu, atbyteslen: %lu\n", byteslen,
                          atbytes->len);
    ret = 1;
    goto exit;
  }
  memcpy(atbytes->bytes, bytes, byteslen);
  atbytes->olen = byteslen;
  ret = 0;
  goto exit;
exit: { return ret; }
}

int atclient_atbytes_convert(atclient_atbytes *atbytes, const char *str, const size_t strlen) {
  int ret = 1;
  if (strlen > atbytes->len) {
    atclient_atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR,
                          "strlen is greater than atbyteslen. strlen: %lu, atbyteslen: %lu\n", strlen, atbytes->len);
    ret = 1;
    goto exit;
  }
  memcpy(atbytes->bytes, (unsigned char *)str, strlen);
  atbytes->olen = strlen;
  ret = 0;
  goto exit;
exit: { return ret; }
}

int atclient_atbytes_convert_atstr(atclient_atbytes *atbytes, const atclient_atstr atstr) {
  int ret = atclient_atbytes_convert(atbytes, atstr.str, atstr.olen);
  if (ret != 0) {
    atclient_atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atclient_atbytes_convert failed");
    goto exit;
  }
exit: { return ret; }
}

void atclient_atbytes_free(atclient_atbytes *atbytes) { free(atbytes->bytes); }
