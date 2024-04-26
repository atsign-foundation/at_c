#ifndef ATCHOPS_SHA_H
#define ATCHOPS_SHA_H

#include <mbedtls/md.h>
#include <stddef.h>

/**
 * @brief SHA Hash an input buffer
 *
 * @param md_type the type of hash to use (e.g. MBEDTLS_MD_SHA256)
 * @param input the input to hash (in raw bytes)
 * @param inputlen the length of the input buffer (most likely strlen(input))
 * @param output (out) the output buffer to write the hash to
 * @param outputsize the size of the output buffer, typically the size of the hash (e.g. 32 bytes = 256 bits for
 * SHA256). Ensure that your buffer is large enough to hold the hash.
 * @param outputlen the length of the output buffer, you will typically expect the output length to be the same as the
 * output size
 * @return int
 */
int atchops_sha_hash(const mbedtls_md_type_t md_type, const unsigned char *input, const size_t inputlen,
                     unsigned char *output, const size_t outputsize, size_t *outputlen);

#endif
