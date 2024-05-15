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


/**
 * @brief calculate the size of the base64 encoded string. This function is usually called before encoding to allocate the optimal buffer size
 * 
 * @param plaintextsize the size of the original plain text (to be encoded)
 * @return size_t the output buffer size needed to store the encoded base64 string
 */
size_t atchops_base64_encoded_size(const size_t plaintextsize);

/**
 * @brief calculate the size of the base64 decoded string. This function is usually called before decoding to allocate the optimal buffer size
 * 
 * @param encodedsize the size of the base64 encoded string (to be decoded)
 * @return size_t the output buffer size needed to store the decoded plain text
 */
size_t atchops_base64_decoded_size(const size_t encodedsize);

#endif