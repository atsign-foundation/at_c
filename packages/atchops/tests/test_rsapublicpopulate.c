
#include <stdio.h>
#include <string.h>
#include "atchops/rsa.h"

#define PUBLIC_KEY_BASE64 "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAsuuD88vWQ3Zunves9w5o3pLQ+7ClKONAMftVQ9dirJt6VD0xg5DNzX+EqdgE3MumWwkR0hFrce3T3wvx9ae8kvSjlS7QJsfGk9EjYk/lhrHJbISP5/1z/owo8a6WMH+J7YF9ouqeoZaP2YlvIt/gMsocPLmLlTFMjB7+9BGqEzdPjeUBfZe+C5C2C+3F8n2Wsgz02ScWyxdlhKEM+GViYYBZONBHgcNN44i4P09IcNYG0tM/ex4WbP0D7U2g0fRCWKtu3mWoERWenpu3rK4406ZhmkyZrWYxKJleqPxDrXbyJkXtbVYiNtg1hgCovOwQRl0eWa98aEVz0sqRy6i7DQIDAQAB"

int main()
{
    int ret = 1;

    size_t publickeybase64len = strlen(PUBLIC_KEY_BASE64);
    const unsigned char *publickeybase64 = PUBLIC_KEY_BASE64;

    atchops_rsa_publickey publickeystruct;
    ret = atchops_rsa_populate_publickey(publickeybase64, publickeybase64len, &publickeystruct);
    if (ret != 0)
    {
        goto ret;
    }

    if (publickeystruct.n_param.len <= 0)
    {
        ret = 1;
        goto ret;
    }

    if (publickeystruct.e_param.len <= 0)
    {
        ret = 1;
        goto ret;
    }

    // printf("n: ");
    // printx(publickeystruct.n_param.n, publickeystruct.n_param.len);
    // printf("e: ");
    // printx(publickeystruct.e_param.e, publickeystruct.e_param.len);

    goto ret;
    ret:
    {
        return ret;
    }
}