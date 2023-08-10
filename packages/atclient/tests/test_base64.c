#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "atchops/base64.h"

#define SRC_STRING "1DPU9OP3CYvamnVBMwGgL7fm8yB1klAap0Uc5Z9R79g="
#define DST_BYTES_ALLOCATED 5000

int main()
{
    int retval;

    const unsigned char *src = SRC_STRING;
    const size_t srclen = strlen(src);

    size_t dstlen = DST_BYTES_ALLOCATED;
    unsigned char *dst = malloc(sizeof(unsigned char) * dstlen);

    size_t dstlen2 = DST_BYTES_ALLOCATED;
    unsigned char *dst2 = malloc(sizeof(unsigned char) * dstlen);

    size_t *olen = malloc(sizeof(size_t));

    retval = atchops_base64_decode(dst, dstlen, olen, src, srclen);
    if(retval)
    {
        goto ret;
    }
    // printf("olen: %lu\n", *olen);

    retval = atchops_base64_encode(dst2, dstlen2, olen, dst, *olen);
    if(retval)
    {
        goto ret;
    }
    // printf("olen: %lu\n", *olen);

    free(dst);
    free(dst2);
    free(olen);

    goto ret;

    ret: {
        return retval;
    }
}