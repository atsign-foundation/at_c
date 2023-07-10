
#ifdef __cplusplus
extern "C"
{
#endif

#include <stdio.h>
#include "byteutil.h"

void printx(unsigned char *data, size_t len)
{
    // TODO check len here, error handle return an int
    for (size_t i = 0; i < len; i++)
    {
        printf("%02x ", data[i]);
    }
    printf("\n");
}

void copy(unsigned char *dst, unsigned char *src, size_t len)
{
    // TODO: check len here, error handle return an int
    for (size_t i = 0; i < len; i++)
    {
        dst[i] = src[i];
    }
}

#ifdef __cplusplus
}
#endif