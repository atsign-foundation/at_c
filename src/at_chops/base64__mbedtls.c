#pragma once

#ifdef BUILD_MBEDTLS

#ifdef __cplusplus
extern "C"
{
#endif

#include <stddef.h>
#include <mbedtls/base64.h>

  int base64Decode(unsigned char *dst, size_t dlen, size_t *olen,
                   const unsigned char *src, size_t slen)
  {
    return mbedtls_base64_decode(dst, dlen, olen, src, slen);
  }

  int base64Encode(unsigned char *dst, size_t dlen, size_t *olen,
                   const unsigned char *src, size_t slen)
  {
    return mbedtls_base64_encode(dst, dlen, olen, src, slen);
  }

#ifdef __cplusplus
}
#endif

#endif
