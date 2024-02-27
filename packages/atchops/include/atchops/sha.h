#ifndef ATCHOPS_SHA_H
#define ATCHOPS_SHA_H

#include <mbedtls/md.h>

int atchops_sha_hash(const mbedtls_md_type_t md_type, const unsigned char *input, const unsigned long inputlen,
                     unsigned char *output, const unsigned long outputlen, unsigned long *outputolen);

#endif
