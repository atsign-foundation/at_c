#include "atchops/base64.h"
#include <atlogger/atlogger.h>
#include <mbedtls/base64.h>
#include <stddef.h>

#define TAG "base64"

#define MAX(a, b) ((a) > (b) ? (a) : (b))

int atchops_base64_encode(const unsigned char *src, const size_t srclen, unsigned char *dst, const size_t dstsize,
                          size_t *dstlen) {
  int ret = 1;
  if (src == NULL || srclen <= 0 || dstsize <= 0) {
    ret = 1;
    atlogger_log("base64", ATLOGGER_LOGGING_LEVEL_ERROR, "atchops_base64_encode: Invalid arguments\n");
    atlogger_log("base64", ATLOGGER_LOGGING_LEVEL_ERROR, "src: %p, srclen: %d, dst: %p, dstsize: %d\n", src, srclen, dst,
                 dstsize);
    goto exit;
  }
  if (dstlen == NULL) {
    size_t x; // throw away variable
    ret = mbedtls_base64_encode(dst, dstsize, &x, src, srclen);
  } else {
    ret = mbedtls_base64_encode(dst, dstsize, dstlen, src, srclen);
  }
  goto exit;
exit: { return ret; }
}

int atchops_base64_decode(const unsigned char *src, const size_t srclen, unsigned char *dst, const size_t dstsize,
                          size_t *dstlen) {
  int ret = 1;
  if (src == NULL || srclen <= 0 || dstsize <= 0) {
    ret = 1;
    atlogger_log("base64", ATLOGGER_LOGGING_LEVEL_ERROR, "atchops_base64_decode: Invalid arguments\n");
    // log them
    atlogger_log("base64", ATLOGGER_LOGGING_LEVEL_ERROR, "src: %p, srclen: %d, dst: %p, dstsize: %d\n", src, srclen, dst,
                 dstsize);
    goto exit;
  }
  if (dstlen == NULL) {
    size_t x; // throw away variable
    ret = mbedtls_base64_decode(dst, dstsize, &x, src, srclen);
  } else {
    ret = mbedtls_base64_decode(dst, dstsize, dstlen, src, srclen);
  }
  goto exit;
exit: { return ret; }
}

size_t atchops_base64_encoded_size(const size_t plaintextsize) {
  return MAX((size_t)(plaintextsize * 3 / 2 + 1), 16); // add 0.5 to ceiling
}

size_t atchops_base64_decoded_size(const size_t encodedsize) {
  return MAX((size_t)(encodedsize * 3 / 4 + 1), 16); // add 0.5 to ceiling
}
