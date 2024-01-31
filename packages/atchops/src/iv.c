#include <mbedtls/entropy.h>
#include <mbedtls/ctr_drbg.h>
#include <string.h>
#include "atchops/iv.h"
#include "atchops/base64.h"
#include "atchops/constants.h"

int atchops_iv_generate(unsigned char *iv)
{
    int ret = 1;
    mbedtls_entropy_context entropy;
    mbedtls_ctr_drbg_context ctr_drbg;

    mbedtls_entropy_init(&entropy);
    mbedtls_ctr_drbg_init(&ctr_drbg);

    if ((ret = mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func, &entropy, (const unsigned char *)ATCHOPS_RNG_PERSONALIZATION, strlen(ATCHOPS_RNG_PERSONALIZATION))) != 0)
    {
        // printf("Error initializing CTR_DRBG\n");
        goto exit;
    }

    if ((ret = mbedtls_ctr_drbg_random(&ctr_drbg, iv, ATCHOPS_IV_SIZE)) != 0)
    {
        // printf("Error generating random IV\n");
        goto exit;
    }

    // printf("Generated IV: ");
    // for (int i = 0; i < ATCHOPS_IV_SIZE; i++) {
    //     printf("%02x", iv[i]);
    // }
    // printf("\n");

    goto exit;

exit:
{
    mbedtls_ctr_drbg_free(&ctr_drbg);
    mbedtls_entropy_free(&entropy);
    return ret;
}
}

int atchops_iv_generate_base64(unsigned char *ivbase64, const unsigned long ivbase64len, unsigned long *ivbase64olen)
{
    int ret = 1;

    unsigned char iv[ATCHOPS_IV_SIZE];

    ret = atchops_iv_generate(iv);
    if (ret != 0)
    {
        goto exit;
    }

    ret = atchops_base64_encode(iv, ATCHOPS_IV_SIZE, ivbase64, ivbase64len, ivbase64olen);
    if (ret != 0)
    {
        goto exit;
    }

    goto exit;
exit:
{
    return ret;
}
}