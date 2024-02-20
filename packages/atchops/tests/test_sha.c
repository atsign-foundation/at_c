#include "atchops/sha.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main() {
  int ret = 1;

  const char *src = "Hello!";

  const unsigned long dstlen = 32;
  unsigned char *dst = calloc(dstlen, sizeof(unsigned char));
  memset(dst, 0, dstlen);
  unsigned long dstolen = 0;

  ret = atchops_sha_hash(MBEDTLS_MD_SHA256, (const unsigned char *)src, strlen(src), dst, dstlen, &dstolen);
  if (ret != 0) {
    printf("atchops_sha_hash (failed): %d\n", ret);
    goto exit;
  }
  printf("atchops_sha_hash (success): %d\n", ret);

  if (dstolen <= 0) {
    ret = 1;
    printf("dstolen (failed): %d\n", ret);
    goto exit;
  }

  printf("dst: ");
  for (int i = 0; i < dstolen; i++) {
    printf("%02x ", dst[i]);
  }
  printf("\n");

  ret = 0;

  goto exit;

exit: {
  free(dst);
  return ret;
}
}
