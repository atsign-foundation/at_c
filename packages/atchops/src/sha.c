#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <mbedtls/md.h>
#include "atchops/sha.h"

int atchops_sha_hash(unsigned char *output, unsigned long outputlen, unsigned long *outputolen, const unsigned char *input, const unsigned long inputlen, atchops_md_type mdtype)
{
    int ret = 1;

    mbedtls_md_context_t md_ctx;
    mbedtls_md_init(&md_ctx);
    mbedtls_md_type_t md_type = mdtype;

    ret = mbedtls_md_setup(&md_ctx, mbedtls_md_info_from_type(md_type), 0);
    if (ret != 0)
        goto ret;

    ret = mbedtls_md_starts(&md_ctx);
    if (ret != 0)
        goto ret;

    ret = mbedtls_md_update(&md_ctx, input, inputlen);
    if (ret != 0)
        goto ret;

    unsigned char *hash = malloc(sizeof(unsigned char) * outputlen);
    memset(hash, 0, outputlen);

    ret = mbedtls_md_finish(&md_ctx, hash);
    if (ret != 0)
        goto ret;

    memcpy(output, hash, outputlen);
    
    int i = 0;
    while(i < outputlen && *(hash + i++) != '\0')
    {
        *outputolen += 1;
    }

    mbedtls_md_free(&md_ctx);

    goto ret;
    ret: {
        return ret;
    }
}
