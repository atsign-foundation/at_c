#ifndef ATCHOPS_SHA_H
#define ATCHOPS_SHA_H

#include <atchops/constants.h>
#include <stddef.h>

typedef enum atchops_md_type {
  ATCHOPS_MD_NONE = 0,
  ATCHOPS_MD_MD5,
  ATCHOPS_MD_RIPEMD160,
  ATCHOPS_MD_SHA1,
  ATCHOPS_MD_SHA224,
  ATCHOPS_MD_SHA256,
  ATCHOPS_MD_SHA384,
  ATCHOPS_MD_SHA512,
  ATCHOPS_MD_SHA3_224,
  ATCHOPS_MD_SHA3_256,
  ATCHOPS_MD_SHA3_384,
  ATCHOPS_MD_SHA3_512,
} atchops_md_type;

/**
 * @brief SHA Hash an input buffer
 *
 * @param md_type the type of hash to use (e.g. MBEDTLS_MD_SHA256)
 * @param input the input to hash (in raw bytes)
 * @param input_len the length of the input buffer (most likely strlen(input))
 * @param output (out) the output buffer to write the hash to. The length of this buffer should correspond to the hash
 * type (e.g. 32 bytes for SHA256 (256 bits = 32 bytes))
 * @return int 0 on success
 */
int atchops_sha_hash(const atchops_md_type md_type, const unsigned char *input, const size_t input_len,
                     unsigned char *output);

#endif
