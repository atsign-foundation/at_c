#include "atchops/aes.h"
#include "atchops/base64.h"
#include "atchops/constants.h"
#include "atchops/mbedtls.h"
#include <string.h>
#include <stddef.h>
#include <atlogger/atlogger.h>

#define TAG "aes"

int atchops_aes_generate_key(unsigned char *key, const enum atchops_aes_size keybits) {
  int ret = 1;

  /*
   * 1. Validate arguments
   */
  if(key == NULL) {
    ret = 1;
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "key is NULL\n");
    return ret;
  }

  if(keybits != ATCHOPS_AES_256) {
    ret = 1;
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "Unsupported keybits\n");
    return ret;
  }

  /*
   * 2. Variables
   */
  const char *personlization = ATCHOPS_RNG_PERSONALIZATION;
  const size_t key_size = keybits / 8;

  // note: To use the AES generator, you need to have the modules enabled in the mbedtls/config.h files
  // (MBEDTLS_CTR_DRBG_C and MBEDTLS_ENTROPY_C), see How do I configure Mbed TLS.
  // https://mbed-tls.readthedocs.io/en/latest/kb/how-to/generate-an-aes-key/

  mbedtls_ctr_drbg_context ctr_drbg;
  mbedtls_ctr_drbg_init(&ctr_drbg);

  mbedtls_entropy_context entropy;
  mbedtls_entropy_init(&entropy);

  /*
   * 3. Seed the random number generator
   */
  if ((ret = mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func, &entropy, (unsigned char *)personlization, strlen(personlization))) != 0) {
    goto exit;
  }

  /*
   * 4. Generate the key
   */
  if ((ret = mbedtls_ctr_drbg_random(&ctr_drbg, key, key_size)) != 0) {
    goto exit;
  }

  goto exit;

exit: {
  mbedtls_ctr_drbg_free(&ctr_drbg);
  mbedtls_entropy_free(&entropy);
  return ret;
}
}
