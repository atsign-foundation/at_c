#include "atchops/base64.h"
#include <mbedtls/base64.h>
#include <stddef.h>

#define MAX(a, b) ((a) > (b) ? (a) : (b))

int atchops_base64_encode(const unsigned char *src, const size_t srclen, unsigned char *dst, const size_t dstsize,
                          size_t *dstlen) {
  return mbedtls_base64_encode(dst, dstsize, dstlen, src, srclen);
}

int atchops_base64_decode(const unsigned char *src, const size_t srclen, unsigned char *dst, const size_t dstsize,
                          size_t *dstlen) {
  return mbedtls_base64_decode(dst, dstsize, dstlen, src, srclen);
}

size_t atchops_base64_encoded_size(const size_t plaintextsize) {
  return MAX((size_t)(plaintextsize * 3 / 2 + 1), 16); // add 0.5 to ceiling
}

size_t atchops_base64_decoded_size(const size_t encodedsize) {
  return MAX((size_t)(encodedsize * 3 / 4 + 1), 16); // add 0.5 to ceiling
}
