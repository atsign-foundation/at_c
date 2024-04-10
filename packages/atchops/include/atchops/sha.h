#ifndef ATCHOPS_SHA_H
#define ATCHOPS_SHA_H

#include <mbedtls/md.h>
#include <stddef.h>

int atchops_sha_hash(const mbedtls_md_type_t md_type, const unsigned char *input, const size_t inputlen,
                     unsigned char *output, const size_t outputlen, size_t *outputolen);

#endif
