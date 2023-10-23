#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "atchops/sha.h"

int main()
{
    int ret = 1;

    const char *src = "Hello!";

    const unsigned long dstlen = 32;
    unsigned char *dst = calloc(dstlen, sizeof(unsigned char));
    unsigned long dstolen;

    ret = atchops_sha_hash(ATCHOPS_MD_SHA256, (const unsigned char *) src, strlen(src), dst, dstlen, &dstolen);
    if(ret != 0)
    {
        printf("failed | atchops_sha_hash: %d\n", ret);
        goto exit;
    }

    goto exit;

exit: {
    return ret;
}
}