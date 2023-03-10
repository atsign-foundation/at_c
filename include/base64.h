#pragma once

#ifdef __cplusplus
extern "C"
{
#endif

#include <stddef.h>

  // TODO

  /**
   * \brief          Decode a base64-formatted buffer
   *
   * \param dst      destination buffer (can be NULL for checking size)
   * \param dlen     size of the destination buffer
   * \param olen     number of bytes written
   * \param src      source buffer
   * \param slen     amount of data to be decoded
   *
   * \return         0 if successful, MBEDTLS_ERR_BASE64_BUFFER_TOO_SMALL, or
   *                 MBEDTLS_ERR_BASE64_INVALID_CHARACTER if the input data is
   *                 not correct. *olen is always updated to reflect the amount
   *                 of data that has (or would have) been written.
   *
   * \note           Call this function with *dst = NULL or dlen = 0 to obtain
   *                 the required buffer size in *olen
   */
  extern int base64Decode(unsigned char *dst, size_t dlen, size_t *olen,
                           const unsigned char *src, size_t slen);

  /**
   * \brief          Encode a base64-formatted buffer
   *
   * \param dst      destination buffer (can be NULL for checking size)
   * \param dlen     size of the destination buffer
   * \param olen     number of bytes written
   * \param src      source buffer
   * \param slen     amount of data to be decoded
   *
   * \return         0 if successful, MBEDTLS_ERR_BASE64_BUFFER_TOO_SMALL, or
   *                 MBEDTLS_ERR_BASE64_INVALID_CHARACTER if the input data is
   *                 not correct. *olen is always updated to reflect the amount
   *                 of data that has (or would have) been written.
   *
   * \note           Call this function with *dst = NULL or dlen = 0 to obtain
   *                 the required buffer size in *olen
   */
  extern int base64Encode(unsigned char *dst, size_t dlen, size_t *olen,
                           const unsigned char *src, size_t slen);

#ifdef __cplusplus
}
#endif