#include "atchops/aes.h"
#include "atchops/base64.h"
#include "atchops/constants.h"
#include <mbedtls/ctr_drbg.h>
#include <mbedtls/entropy.h>
#include <string.h>
#include <stddef.h>

int atchops_aes_generate_key(unsigned char *key, const enum atchops_aes_size keybits) {
  int ret = 1;

  const char *pers = ATCHOPS_RNG_PERSONALIZATION;
  const size_t keybytes = keybits / 8;

  // note: To use the AES generator, you need to have the modules enabled in the mbedtls/config.h files
  // (MBEDTLS_CTR_DRBG_C and MBEDTLS_ENTROPY_C), see How do I configure Mbed TLS.
  // https://mbed-tls.readthedocs.io/en/latest/kb/how-to/generate-an-aes-key/

  mbedtls_ctr_drbg_context ctr_drbg;
  mbedtls_ctr_drbg_init(&ctr_drbg);

  mbedtls_entropy_context entropy;
  mbedtls_entropy_init(&entropy);

  if ((ret = mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func, &entropy, (unsigned char *)pers, strlen(pers))) !=
      0) {
    goto exit;
  }

  if ((ret = mbedtls_ctr_drbg_random(&ctr_drbg, key, keybytes)) != 0) {
    goto exit;
  }

  goto exit;

exit: {
  mbedtls_ctr_drbg_free(&ctr_drbg);
  mbedtls_entropy_free(&entropy);
  return ret;
}
}

int atchops_aes_generate_keybase64(unsigned char *keybase64, const size_t keybase64len,
                                   size_t *keybase64olen, const enum atchops_aes_size keybits) {
  int ret = 1;

  const size_t keysize = keybits / 8;
  unsigned char key[keysize];
  memset(key, 0, keysize);

  ret = atchops_aes_generate_key(key, keybits);
  if (ret != 0) {
    goto exit;
  }

  ret = atchops_base64_encode(key, keysize, keybase64, keybase64len, keybase64olen);
  if (ret != 0) {
    goto exit;
  }

  goto exit;

exit: { return ret; }
}
