#include "atclient/atsign.h"
#include "atclient/constants.h"
#include "atlogger/atlogger.h"
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define TAG "atsign"

int atclient_atsign_init(atclient_atsign *atsign, const char *atsign_str) {
  int ret = 0;

  const size_t maxatlen = ATCLIENT_ATSIGN_FULL_LEN + 1;
  // atsign_str is longer than expected or null/empty
  if ((strlen(atsign_str) > maxatlen) || (atsign_str == NULL) || (strlen(atsign_str) == 0)) {
    ret = 1;
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atclient_atsign_init: %d\n", ret);
    return ret;
  }

  memset(atsign, 0, sizeof(atclient_atsign));
  atsign->atsign = malloc(strlen(atsign_str) + 1);

  size_t atolen = 0;
  ret = atclient_atsign_with_at_symbol(atsign->atsign, maxatlen, &(atolen), atsign_str, strlen(atsign_str));
  if (ret != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atclient_atsign_with_at_symbol failed\n");
    return ret;
  }

  atsign->without_prefix_str = atsign->atsign + 1;
  return ret;
}

void atclient_atsign_free(atclient_atsign *atsign) { free(atsign->atsign); }

int atclient_atsign_without_at_symbol(char *atsign, const size_t atsignlen, size_t *atsignolen,
                                      const char *originalatsign, const size_t originalatsignlen) {
  int ret = 1;
  if (atsignlen + 1 < originalatsignlen) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR,
                 "atsignlen might be too low. consider allocating more buffer space. atsignlen: %d\n", atsignlen);
    ret = 1;
    goto exit;
  }

  if (originalatsignlen <= 0) {
    ret = 2;
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "originalatsignlen is <= 0: %lu\n", originalatsignlen);
    goto exit;
  }

  if (originalatsign[0] != '@') {
    // it did not begin with an `@` to begin with
    ret = 0;
    goto exit;
  }

  strncpy(atsign, originalatsign + 1, originalatsignlen - 1);
  atsign[originalatsignlen - 1] = '\0';
  *atsignolen = originalatsignlen - 1;
  ret = 0;
  goto exit;
exit: { return ret; }
}

int atclient_atsign_with_at_symbol(char *atsign, const size_t atsignsize, size_t *atsignolen,
                                   const char *originalatsign, const size_t originalatsignlen) {
  if (atsignsize + 1 < originalatsignlen) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR,
                 "atsignsize might be too low. consider allocating more buffer space. atsignsize: %d\n", atsignsize);
    return 1;
  }

  if (originalatsignlen <= 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "originalatsignlen is <= 0: %lu\n", originalatsignlen);
    return 2;
  }

  memset(atsign, 0, atsignsize);
  if(originalatsign[0] != '@') {
    atsign[0] = '@';
    strncpy(atsign + 1, originalatsign, originalatsignlen);
    *atsignolen = originalatsignlen + 1;
  } else {
    strncpy(atsign, originalatsign, originalatsignlen);
    *atsignolen = originalatsignlen;
  }
  return 0;
}
