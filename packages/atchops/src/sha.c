#include "atchops/sha.h"
#include <atlogger/atlogger.h>
#include <mbedtls/md.h>
#include <stddef.h>

#define TAG "sha"

int atchops_sha_hash(const atchops_md_type md_type, const unsigned char *input, const size_t input_len,
                     unsigned char *output) {
  int ret = 1;

  /*
   * 1. Validate arguments
   */

  if (md_type != ATCHOPS_MD_SHA256) {
    ret = 1;
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "Unsupported md_type\n");
    return ret;
  }

  if (input == NULL) {
    ret = 1;
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "input is NULL\n");
    return ret;
  }

  if (input_len <= 0) {
    ret = 1;
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "input_len is less than or equal to 0\n");
    return ret;
  }

  if (output == NULL) {
    ret = 1;
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "output is NULL\n");
    return ret;
  }

  /*
   * 2. Variables
   */
  mbedtls_md_context_t md_ctx;
  mbedtls_md_init(&md_ctx);

  /*
   * 3. Prepare the hash context
   */
  if ((ret = mbedtls_md_setup(&md_ctx, mbedtls_md_info_from_type(atchops_mbedtls_md_map[md_type]), 0)) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "Failed to setup the hash context\n");
    goto exit;
  }

  /*
   * 4. Hash
   */
  if ((ret = mbedtls_md_starts(&md_ctx)) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "Failed to start the hash\n");
    goto exit;
  }

  if ((ret = mbedtls_md_update(&md_ctx, input, input_len)) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "Failed to update the hash\n");
    goto exit;
  }

  if ((ret = mbedtls_md_finish(&md_ctx, output)) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "Failed to finish the hash\n");
    goto exit;
  }

  ret = 0;
  goto exit;
exit: {
  mbedtls_md_free(&md_ctx);
  return ret;
}
}
