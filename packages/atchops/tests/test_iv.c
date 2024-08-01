#include "atchops/iv.h"
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <atlogger/atlogger.h>

#define TAG "test_iv"

int main() {
  int ret = 1;

  const size_t ivsize = ATCHOPS_IV_BUFFER_SIZE;
  unsigned char iv[ivsize];
  memset(iv, 0, sizeof(unsigned char) * ivsize);

  if ((ret = atchops_iv_generate(iv)) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "Failed to generate IV\n");
    goto exit;
  }
  
  atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_INFO, "IV (%d bytes): ", ivsize);
  for (int i = 0; i < ivsize; i++) {
    printf("%02x ", iv[i]);
  }
  printf("\n");

exit: { return ret; }
}
