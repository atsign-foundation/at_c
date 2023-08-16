#pragma once

typedef enum {
    ATCHOPS_MD_NONE=0,    /**< None. */
    ATCHOPS_MD_MD5,       /**< The MD5 message digest. */
    ATCHOPS_MD_SHA1,      /**< The SHA-1 message digest. */
    ATCHOPS_MD_SHA224,    /**< The SHA-224 message digest. */
    ATCHOPS_MD_SHA256,    /**< The SHA-256 message digest. */
    ATCHOPS_MD_SHA384,    /**< The SHA-384 message digest. */
    ATCHOPS_MD_SHA512,    /**< The SHA-512 message digest. */
    ATCHOPS_MD_RIPEMD160,
} atchops_md_type;

int atchops_sha_hash(atchops_md_type mdtype, const unsigned char *input, const unsigned long inputlen, unsigned char *output, unsigned long outputlen, unsigned long *outputolen);
