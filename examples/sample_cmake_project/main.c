#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <atchops/base64.h>

int main()
{
    const char *src = "Hello, World!\n";
    const unsigned long srclen = strlen(src);

    const unsigned long dstlen = 2048;
    unsigned char *dst = malloc(sizeof(unsigned char) * dstlen);
    memset(dst, 0, dstlen);
    unsigned long olen = 0;

    int ret = atchops_base64_encode((const unsigned char *) src, srclen, dst, dstlen, &olen);

    printf("atchops_base64_encode: %d\n", ret);

    printf("dst: %s\n", dst);
    for(int i = 0; i < olen; i++)
    {
        printf("%02x ", *(dst + i));
    }
    printf("\n");

    return 0;
}
