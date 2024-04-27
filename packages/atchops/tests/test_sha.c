#include "atchops/sha.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stddef.h>

// dst: 33 4d 01 6f 75 5c d6 dc 58 c5 3a 86 e1 83 88 2f 8e c1 4f 52 fb 05 34 58 87 c8 a5 ed d4 2c 87 b7
#define EXPECTED_HASH {0x33, 0x4d, 0x01, 0x6f, 0x75, 0x5c, 0xd6, 0xdc, 0x58, 0xc5, 0x3a, 0x86, 0xe1, 0x83, 0x88, 0x2f, 0x8e, 0xc1, 0x4f, 0x52, 0xfb, 0x05, 0x34, 0x58, 0x87, 0xc8, 0xa5, 0xed, 0xd4, 0x2c, 0x87, 0xb7}

#define HASH_SIZE 32

int main() {
  int ret = 1;

  const char *src = "Hello!";

  unsigned char dst[HASH_SIZE];
  memset(dst, 0, sizeof(unsigned char) * HASH_SIZE);

  const unsigned char expected_hash[HASH_SIZE] = EXPECTED_HASH;

  ret = atchops_sha_hash(MBEDTLS_MD_SHA256, (const unsigned char *)src, strlen(src), dst);
  if (ret != 0) {
    printf("atchops_sha_hash (failed): %d\n", ret);
    goto exit;
  }
  printf("atchops_sha_hash (success): %d\n", ret);


  printf("dst: ");
  for (int i = 0; i < HASH_SIZE; i++) {
    printf("%02x ", dst[i]);
  }
  printf("\n");

  ret = memcmp(dst, expected_hash, HASH_SIZE);
  if (ret != 0) {
    printf("memcmp (failed): %d\n", ret);
    goto exit;
  }
  printf("memcmp (success): %d\n", ret);

  ret = 0;

  goto exit;

exit: {
  return ret;
}
}
