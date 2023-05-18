#pragma once

#ifdef __cplusplus
extern "C"
{
#endif

#include <stddef.h>

/**
 * @brief Encodes a string to base64
 * 
 * @param destination the result
 * @param destination_len the size of the result allocated
 * @param written_len the length of the result after operation
 * @param src the plain text string to encode
 * @param src_len the size of the plain text string to encode
 * @return int `0,` if successful
 */
int atchops_base64_encode(unsigned char *dst, size_t dstlen, size_t *writtenlen, const unsigned char *src, const size_t srclen);

/**
 * @brief Decodes a base64 string
 * 
 * @param dst the result
 * @param dstlen the size of the result allocated
 * @param writtenlen the length of the result after operation
 * @param src the base64 encoded string to decode
 * @param srclen the length of the base64 encoded string to decode
 * @return int `0`, if successful
 */
int atchops_base64_decode(unsigned char * dst, size_t dstlen, size_t *writtenlen, const unsigned char *src, const size_t srclen);

#ifdef __cplusplus
}
#endif