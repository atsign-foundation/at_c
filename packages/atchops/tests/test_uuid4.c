#include "atchops/uuid.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stddef.h>

int main() {

  int ret = 1;

  const size_t dstlen = 37;
  char *dst = malloc(sizeof(char) * dstlen);
  memset(dst, 0, dstlen);

  ret = atchops_uuid_init();
  if (ret != 0) {
    goto exit;
  }

  atchops_uuid_generate(dst, dstlen);
  printf("(%d): %s\n", (int)strlen(dst), dst);
  if (strlen(dst) <= 0) {
    ret = 1;
    goto exit;
  }

  memset(dst, 0, dstlen);
  atchops_uuid_generate(dst, dstlen);
  printf("(%d): %s\n", (int)strlen(dst), dst);
  if (strlen(dst) <= 0) {
    ret = 1;
    goto exit;
  }

  memset(dst, 0, dstlen);
  atchops_uuid_generate(dst, dstlen);
  printf("(%d): %s\n", (int)strlen(dst), dst);

  if (strlen(dst) <= 0) {
    ret = 1;
    goto exit;
  }

  goto exit;

exit: {
  free(dst);
  return ret;
}
}
