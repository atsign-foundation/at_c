#include "atclient/atsign.h"
#include "atlogger/atlogger.h"
#include <stdio.h>
#include <string.h>

#define TAG "atsign"

int atclient_atsign_init(atclient_atsign *atsign, const char *atsign_str) {
  int ret = 0;

  // atsign_str is longer than expected or null/empty
  if ((strlen(atsign_str) > MAX_ATSIGN_STR_BUFFER) || (atsign_str == NULL) || (strlen(atsign_str) == 0)) {
    ret = 1;
    atclient_atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atclient_atsign_init: %d\n", ret);
    return ret;
  }

  memset(atsign, 0, sizeof(atclient_atsign));
  atsign->atsign = malloc(strlen(atsign_str) + 1);

  const unsigned long maxatlen = MAX_ATSIGN_STR_BUFFER;
  unsigned long atolen = 0;
  ret = atclient_atsign_with_at_symbol(atsign->atsign, maxatlen, &(atolen), atsign_str, strlen(atsign_str));
  if (ret != 0) {
    atclient_atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atclient_atsign_with_at_symbol failed\n");
    return ret;
  }

  atsign->without_prefix_str = atsign->atsign + 1;
  return ret;
}

void atclient_atsign_free(atclient_atsign *atsign) { free(atsign->atsign); }

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
  atsign[originalatsignlen - 1] = '\0';
  *atsignolen = originalatsignlen - 1;
  ret = 0;
  goto exit;
exit : { return ret; }
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
    strncpy(atsign, originalatsign, originalatsignlen + 1);
    atsign[originalatsignlen] = '\0';
    ret = 0;
    goto exit;
  }

  atsign[0] = '@';
  strncpy(atsign + 1, originalatsign, originalatsignlen + 1);
  atsign[originalatsignlen + 1] = '\0';
  *atsignolen = originalatsignlen + 1;
  ret = 0;
  goto exit;
exit : { return ret; }
}
