#include "at_client.h"
#include <stdio.h>
#include <string.h>

#ifdef BUILD_MBEDTLS
#include "mbedtls/entropy.h"
#include "mbedtls/ctr_drbg.h"

int at_client::make_aes_key(unsigned char key[32])
{
  mbedtls_ctr_drbg_context ctr_drbg;
  mbedtls_entropy_context entropy;

  const char *pers = (const char *)("aes generate key");
  int ret;

  mbedtls_entropy_init(&entropy);

  mbedtls_ctr_drbg_init(&ctr_drbg);

  if ((ret = mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func, &entropy,
                                   (const unsigned char *)pers, strlen(pers))) != 0)
  {
    printf(" failed\n ! mbedtls_ctr_drbg_init returned -0x%04x\n", -ret);
    return 1;
  }

  if ((ret = mbedtls_ctr_drbg_random(&ctr_drbg, key, 32)) != 0)
  {
    printf(" failed\n ! mbedtls_ctr_drbg_random returned -0x%04x\n", -ret);
    return 1;
  }
  return 0;
}
#endif
