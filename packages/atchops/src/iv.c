#include "atchops/iv.h"
#include "atchops/base64.h"
#include "atchops/constants.h"
#include <atlogger/atlogger.h>
#include <mbedtls/ctr_drbg.h>
#include <mbedtls/entropy.h>
#include <string.h>
#include <stddef.h>

#define TAG "iv"

int atchops_iv_generate(unsigned char *iv) {
  int ret = 1;
  mbedtls_entropy_context entropy;
  mbedtls_ctr_drbg_context ctr_drbg;

  mbedtls_entropy_init(&entropy);
  mbedtls_ctr_drbg_init(&ctr_drbg);

  if ((ret = mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func, &entropy,
                                   (const unsigned char *)ATCHOPS_RNG_PERSONALIZATION,
                                   strlen(ATCHOPS_RNG_PERSONALIZATION))) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "Failed to seed random number generator\n");
    goto exit;
  }

  if ((ret = mbedtls_ctr_drbg_random(&ctr_drbg, iv, ATCHOPS_IV_BUFFER_SIZE)) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "Failed to generate random IV\n");
    goto exit;
  }

  goto exit;

exit: {
  mbedtls_ctr_drbg_free(&ctr_drbg);
  mbedtls_entropy_free(&entropy);
  return ret;
}
}
