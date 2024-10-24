#include "atchops/base64.h"
#include <atlogger/atlogger.h>
#include "atchops/mbedtls.h"
#include <stddef.h>

#define TAG "base64"

#define MAX(a, b) ((a) > (b) ? (a) : (b))

int atchops_base64_encode(const unsigned char *src, const size_t src_len, unsigned char *dst, const size_t dst_size,
                          size_t *dst_len) {
  int ret = 1;

  /*
   * 1. Validate arguments
   */
  if (src == NULL) {
    ret = 1;
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atchops_base64_encode: src is NULL\n");
    return ret;
  }

  if (src_len <= 0) {
    ret = 2;
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atchops_base64_encode: src_len is less than or equal to 0\n");
    return ret;
  }

  if (dst == NULL) {
    ret = 3;
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atchops_base64_encode: dst is NULL\n");
    return ret;
  }

  if (dst_size <= 0) {
    ret = 4;
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atchops_base64_encode: dst_size is less than or equal to 0\n");
    return ret;
  }

  /*
   * 2. Encode
   */
  if (dst_len == NULL) {
    size_t x; // throw away variable
    if((ret = mbedtls_base64_encode(dst, dst_size, &x, src, src_len)) != 0) {
      atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atchops_base64_encode: mbedtls_base64_encode failed\n");
      goto exit;
    }
  } else {
    if((ret = mbedtls_base64_encode(dst, dst_size, dst_len, src, src_len)) != 0) {
      atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atchops_base64_encode: mbedtls_base64_encode failed\n");
      goto exit;
    }
  }
  ret = 0;
  goto exit;
exit: { return ret; }
}

int atchops_base64_decode(const unsigned char *src, const size_t src_len, unsigned char *dst, const size_t dst_size,
                          size_t *dst_len) {
  int ret = 1;

  /*
   * 1. Validate arguments
   */
  if(src == NULL) {
    ret = 1;
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atchops_base64_decode: src is NULL\n");
    return ret;
  }

  if(src_len <= 0) {
    ret = 1;
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atchops_base64_decode: src_len is less than or equal to 0\n");
    return ret;
  }

  if(dst == NULL) {
    ret = 1;
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atchops_base64_decode: dst is NULL\n");
    return ret;
  }

  if(dst_size <= 0) {
    ret = 1;
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atchops_base64_decode: dst_size is less than or equal to 0\n");
    return ret;
  }

  /*
   * 2. Decode
   */
  if (dst_len == NULL) {
    size_t x; // throw away variable
    if((ret = mbedtls_base64_decode(dst, dst_size, &x, src, src_len)) != 0) {
      atlogger_log("base64", ATLOGGER_LOGGING_LEVEL_ERROR, "atchops_base64_decode: mbedtls_base64_decode failed\n");
      goto exit;
    }
  } else {
    if((ret = mbedtls_base64_decode(dst, dst_size, dst_len, src, src_len)) != 0) {
      atlogger_log("base64", ATLOGGER_LOGGING_LEVEL_ERROR, "atchops_base64_decode: mbedtls_base64_decode failed\n");
      goto exit;
    }
  }
  ret = 0;
  goto exit;
exit: { return ret; }
}

size_t atchops_base64_encoded_size(const size_t plaintextsize) {
  return MAX((size_t)(plaintextsize * 3 / 2 + 1), 16); // add 0.5 to ceiling
}

size_t atchops_base64_decoded_size(const size_t encodedsize) {
  return MAX((size_t)(encodedsize * 3 / 4 + 1), 16); // add 0.5 to ceiling
}
