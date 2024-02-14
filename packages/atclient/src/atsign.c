#ifndef ATCLIENT_ATSIGN_H
#define ATCLIENT_ATSIGN_H

#include "atclient/atsign.h"
#include "atlogger/atlogger.h"
#include <stdio.h>
#include <string.h>

#define TAG "atsign"

int atclient_atsign_without_at_symbol(char *atsign, const unsigned long atsignlen, unsigned long *atsignolen,
                                      const char *originalatsign, const unsigned long originalatsignlen) {
  int ret = 1;
  if (atsignlen + 1 < originalatsignlen) {
    atclient_atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR,
                          "atsignlen might be too low. consider allocating more buffer space. atsignlen: %d\n",
                          atsignlen);
    ret = 1;
    goto exit;
  }

  if (originalatsignlen <= 0) {
    ret = 2;
    atclient_atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "originalatsignlen is <= 0: %lu\n", originalatsignlen);
    goto exit;
  }

  if (originalatsign[0] != '@') {
    // it did not begin with an `@` to begin with
    ret = 0;
    goto exit;
  }

  strncpy(atsign, originalatsign + 1, originalatsignlen - 1);
  *atsignolen = originalatsignlen - 1;
  ret = 0;
  goto exit;
exit: { return ret; }
}

int atclient_atsign_with_at_symbol(char *atsign, const unsigned long atsignlen, unsigned long *atsignolen,
                                   const char *originalatsign, const unsigned long originalatsignlen) {
  int ret = 1;
  if (atsignlen + 1 < originalatsignlen) {
    atclient_atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR,
                          "atsignlen might be too low. consider allocating more buffer space. atsignlen: %d\n",
                          atsignlen);
    ret = 1;
    goto exit;
  }

  if (originalatsignlen <= 0) {
    ret = 2;
    atclient_atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "originalatsignlen is <= 0: %lu\n", originalatsignlen);
    goto exit;
  }

  if (originalatsign[0] == '@') {
    // it already began with an x@x
    ret = 0;
    goto exit;
  }

  atsign[0] = '@';
  strncpy(atsign + 1, originalatsign, originalatsignlen);
  *atsignolen = originalatsignlen + 1;
  ret = 0;
  goto exit;
exit: { return ret; }
}

#endif
