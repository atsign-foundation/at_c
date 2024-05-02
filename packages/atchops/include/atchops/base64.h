#ifndef ATCHOPS_BASE64_H
#define ATCHOPS_BASE64_H

#include <stddef.h>

/**
 * @brief Base64 encode some bytes
 *
 * @param src src bytes that you want to encode
 * @param srcsize the length of the src bytes
 * @param dst the buffer where the base64 encoded result will be
 * @param dstsize the buffer length
 * @param dstlen the length of the result after operation
 * @return int 0 on success
 */
int atchops_base64_encode(const unsigned char *src, const size_t srcsize, unsigned char *dst,
                          size_t dstsize, size_t *dstlen);

/**
 * @brief Base64 decode some bytes
 *
 * @param src src bytes that you want to decode
 * @param srcsize the length of the src bytes
 * @param dst the buffer where the base64 decoded result will be
 * @param dstsize the buffer length
 * @param dstlen the length of the result after operation
 * @return int 0 on success
 */
int atchops_base64_decode(const unsigned char *src, const size_t srcsize, unsigned char *dst,
                          size_t dstsize, size_t *dstlen);

#endif