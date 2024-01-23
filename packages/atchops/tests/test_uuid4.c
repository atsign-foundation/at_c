

#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include "atchops/uuid.h"

int main()
{

    int ret = 1;

    const unsigned long dstlen = 37;
    char *dst = malloc(sizeof(char) * dstlen);
    memset(dst, 0, dstlen);

    ret = atchops_uuid_init();
    if (ret != 0)
    {
        goto exit;
    }

    atchops_uuid_generate(dst, dstlen);
    printf("(%d): %s\n", (int) strlen(dst), dst);
    if(strlen(dst) <= 0)
    {
        ret = 1;
        goto exit;
    }

    memset(dst, 0, dstlen);
    atchops_uuid_generate(dst,dstlen);
    printf("(%d): %s\n", (int) strlen(dst), dst);
    if(strlen(dst) <= 0)
    {
        ret = 1;
        goto exit;
    }

    memset(dst, 0, dstlen);
    atchops_uuid_generate(dst,dstlen);
    printf("(%d): %s\n", (int) strlen(dst), dst);

    if(strlen(dst) <= 0)
    {
        ret = 1;
        goto exit;
    }

    goto exit;

exit:
{
    free(dst);
    return ret;
}
}