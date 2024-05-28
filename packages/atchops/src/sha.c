#include "atchops/sha.h"
#include <mbedtls/md.h>
#include <stddef.h>

int atchops_sha_hash(const atchops_md_type mdtype, const unsigned char *input, const size_t inputlen,
                     unsigned char *output) {
  int ret = 1;

  mbedtls_md_context_t md_ctx;
  mbedtls_md_init(&md_ctx);

  ret = mbedtls_md_setup(&md_ctx, mbedtls_md_info_from_type(atchops_mbedtls_md_map[mdtype]), 0);
  if (ret != 0)
    goto ret;

  ret = mbedtls_md_starts(&md_ctx);
  if (ret != 0)
    goto ret;

  ret = mbedtls_md_update(&md_ctx, input, inputlen);
  if (ret != 0)
    goto ret;

  ret = mbedtls_md_finish(&md_ctx, output);
  if (ret != 0)
    goto ret;

  goto ret;
ret: {
  mbedtls_md_free(&md_ctx);
  return ret;
}
}
