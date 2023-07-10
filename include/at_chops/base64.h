#pragma once

#ifdef __cplusplus
extern "C"
{
#endif

#include <stddef.h>

#define MAX_TEXT_LENGTH_FORBASE64_ENCODING_OPERATION 10000 // the max length of base64 encoded text (should be more than enough)

/**
 * @brief Encodes a string to base64
 * 
 * @param destination the result
 * @param destination_len the size of the result allocated
 * @param written_len the length of the result after operation
 * @param src the plain text string to encode
 * @param src_len the size of the plain text string to encode
 * @return int `0,` if successful, 0 if successful, MBEDTLS_ERR_BASE64_BUFFER_TOO_SMALL, or MBEDTLS_ERR_BASE64_INVALID_CHARACTER if the input data is not correct. *olen is always updated to reflect the amount of data that has (or would have) been written.
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