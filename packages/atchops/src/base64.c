#include "atchops/base64.h"
#include <mbedtls/base64.h>
#include <stddef.h>

int atchops_base64_encode(const unsigned char *src, const size_t srclen, unsigned char *dst,
                          const size_t dstlen, size_t *writtenlen) {
  return mbedtls_base64_encode(dst, dstlen, writtenlen, src, srclen);
}

int atchops_base64_decode(const unsigned char *src, const size_t srclen, unsigned char *dst,
                          const size_t dstlen, size_t *writtenlen) {
  return mbedtls_base64_decode(dst, dstlen, writtenlen, src, srclen);
}
