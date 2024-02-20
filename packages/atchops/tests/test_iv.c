#include "atchops/iv.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main() {
  int ret = 1;
  unsigned char iv[ATCHOPS_IV_BUFFER_SIZE];
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

  const unsigned long ivbase64len = 4096;
  unsigned char *ivbase64 = malloc(sizeof(unsigned char) * ivbase64len);
  memset(ivbase64, 0, ivbase64len);
  unsigned long ivbase64olen = 0;
  ret = atchops_iv_generate_base64(ivbase64, ivbase64len, &ivbase64olen);
  if (ret != 0) {
    printf("atchops_iv_generate_base64 (failed): %d\n", ret);
    goto exit;
  }
  printf("ivbase64 (%lu): %s\n", ivbase64olen, ivbase64);

exit: { return ret; }
}
