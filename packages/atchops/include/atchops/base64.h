#ifndef ATCHOPS_BASE64_H
#define ATCHOPS_BASE64_H

#include <stddef.h>

/**
 * @brief Base64 encode some bytes
 *
 * @param src src bytes that you want to encode
 * @param srclen the length of the src bytes
 * @param dst the buffer where the base64 encoded result will be
 * @param dstlen the buffer length
 * @param writtenlen the length of the result after operation
 * @return int 0 on success
 */
int atchops_base64_encode(const unsigned char *src, const size_t srclen, unsigned char *dst,
                          size_t dstlen, size_t *writtenlen);

/**
 * @brief Base64 decode some bytes
 *
 * @param src src bytes that you want to decode
 * @param srclen the length of the src bytes
 * @param dst the buffer where the base64 decoded result will be
 * @param dstlen the buffer length
 * @param writtenlen the length of the result after operation
 * @return int 0 on success
 */
int atchops_base64_decode(const unsigned char *src, const size_t srclen, unsigned char *dst,
                          size_t dstlen, size_t *writtenlen);

#endif