#ifndef ATCHOPS_CONSTANTS_H
#define ATCHOPS_CONSTANTS_H

#define ATCHOPS_RNG_PERSONALIZATION "@atchops12345"

#include "mbedtls/md.h"

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

extern const mbedtls_md_type_t atchops_mbedtls_md_map[];

#endif
