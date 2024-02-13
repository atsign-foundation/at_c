#include "atchops/base64.h"
#include <mbedtls/base64.h>

int atchops_base64_encode(const unsigned char *src, const unsigned long srclen, unsigned char *dst,
                          const unsigned long dstlen, unsigned long *writtenlen) {
  return mbedtls_base64_encode(dst, dstlen, writtenlen, src, srclen);
}

int atchops_base64_decode(const unsigned char *src, const unsigned long srclen, unsigned char *dst,
                          const unsigned long dstlen, unsigned long *writtenlen) {
  return mbedtls_base64_decode(dst, dstlen, writtenlen, src, srclen);
}
