#include "atchops/base64.h"
#include <mbedtls/base64.h>
#include <stddef.h>

int atchops_base64_encode(const unsigned char *src, const size_t srclen, unsigned char *dst,
                          const size_t dstsize, size_t *dstlen) {
  return mbedtls_base64_encode(dst, dstsize, dstlen, src, srclen);
}

int atchops_base64_decode(const unsigned char *src, const size_t srclen, unsigned char *dst,
                          const size_t dstsize, size_t *dstlen) {
  return mbedtls_base64_decode(dst, dstsize, dstlen, src, srclen);
}
