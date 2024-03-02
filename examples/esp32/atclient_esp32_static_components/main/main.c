#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "atchops/base64.h"

void app_main(void)
{
    const char *src = "Lemonade!";
    unsigned long srclen = strlen(src);

    const unsigned long dstlen = 2048;
    const unsigned char *dst = malloc(sizeof(unsigned char) * dstlen);
    memset(dst, 0, dstlen);
    unsigned long dstolen = 0; // written length

    int ret = atchops_base64_encode((const unsigned char *) src, srclen, dst, dstlen, &dstolen);

    printf("atchops_base64_encode: %d\n", ret);

    printf("src: %s\n", src);
    printf("dst: %.*s\n", (int) dstolen, dst);
    printf("dst bytes: \n");
    for(int i = 0; i < dstolen; i++)
    {
        printf("%02x ", *(dst + i));
    }
    printf("\n");
}