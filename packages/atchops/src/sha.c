#include "atchops/sha.h"
#include <mbedtls/md.h>
#include <stdlib.h>
#include <string.h>
#include <stddef.h>

int atchops_sha_hash(mbedtls_md_type_t md_type, const unsigned char *input, const size_t inputlen,
                     unsigned char *output, size_t outputsize, size_t *outputlen) {
  int ret = 1;

  mbedtls_md_context_t md_ctx;
  mbedtls_md_init(&md_ctx);

  ret = mbedtls_md_setup(&md_ctx, mbedtls_md_info_from_type(md_type), 0);
  if (ret != 0)
    goto ret;

  ret = mbedtls_md_starts(&md_ctx);
  if (ret != 0)
    goto ret;

  ret = mbedtls_md_update(&md_ctx, input, inputlen);
  if (ret != 0)
    goto ret;

  unsigned char *hash = malloc(sizeof(unsigned char) * outputsize);
  memset(hash, 0, outputsize);

  ret = mbedtls_md_finish(&md_ctx, hash);
  if (ret != 0)
    goto ret;

  memcpy(output, hash, outputsize);

  int i = 0;
  while (i < outputsize && *(hash + i++) != '\0') {
    *outputlen += 1;
  }
  --(*outputlen); // remove the '\0' at the end of the string

  goto ret;
ret: {
  mbedtls_md_free(&md_ctx);
  return ret;
}
}
