#include "atchops/iv.h"
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main() {
  int ret = 1;

  unsigned char iv[ATCHOPS_IV_BUFFER_SIZE];
  memset(iv, 0, sizeof(unsigned char) * ATCHOPS_IV_BUFFER_SIZE);

  const size_t ivbase64size = 1024;
  unsigned char ivbase64[ivbase64size];
  memset(ivbase64, 0, sizeof(unsigned char) * ivbase64size);
  size_t ivbase64len = 0;

  ret = atchops_iv_generate(iv);
  if (ret != 0) {
    printf("atchops_iv_generate (failed): %d\n", ret);
    goto exit;
  }
  printf("iv: ");
  for (int i = 0; i < ATCHOPS_IV_BUFFER_SIZE; i++) {
    printf("%02x ", iv[i]);
  }
  printf("\n");

exit: { return ret; }
}
