#include <stdlib.h>
#include <mbedtls/md.h>
#include "at_chops/sha.h"

int atchops_sha_hash(const char *input, size_t inputlen, unsigned char **output, atchops_md_type mdtype)
{
    int ret = 1;

    mbedtls_md_context_t md_ctx;
    mbedtls_md_init(&md_ctx);

    mbedtls_md_type_t md_type = mdtype; // TODO dynamic

    ret = mbedtls_md_setup(&md_ctx, mbedtls_md_info_from_type(md_type), 0);
    if (ret != 0)
        goto ret;

    ret = mbedtls_md_starts(&md_ctx);
    if (ret != 0)
        goto ret;

    ret = mbedtls_md_update(&md_ctx, input, inputlen);
    if (ret != 0)
        goto ret;

    const size_t hashlen = mbedtls_md_get_size(mbedtls_md_info_from_type(md_type));
    // printf("hashlen: %lu\n", hashlen);
    unsigned char *hash = malloc(sizeof(unsigned char) * hashlen);

    *output = hash;

    ret = mbedtls_md_finish(&md_ctx, hash);
    if (ret != 0)
        goto ret;

    mbedtls_md_free(&md_ctx);

    goto ret;
    ret: {
        return ret;
    }
}