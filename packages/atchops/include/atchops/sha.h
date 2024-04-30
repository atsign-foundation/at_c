#ifndef ATCHOPS_SHA_H
#define ATCHOPS_SHA_H

#include <mbedtls/md.h>
#include <stddef.h>

/**
 * @brief SHA Hash an input buffer
 *
 * @param mdtype the type of hash to use (e.g. MBEDTLS_MD_SHA256)
 * @param input the input to hash (in raw bytes)
 * @param inputlen the length of the input buffer (most likely strlen(input))
 * @param output (out) the output buffer to write the hash to. The length of this buffer should correspond to the hash
 * type (e.g. 32 bytes for SHA256 (256 bits = 32 bytes))
 * @return int 0 on success
 */
int atchops_sha_hash(const mbedtls_md_type_t mdtype, const unsigned char *input, const size_t inputlen,
                     unsigned char *output);

#endif
