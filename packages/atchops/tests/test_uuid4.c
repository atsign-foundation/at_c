
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include "atchops/3rdparty/uuid4.h"

int main()
{
    int ret = 1;

    const unsigned long buflen = 4096;
    const unsigned char* buf = malloc(sizeof(unsigned char) * buflen);
    memset(buf, 0, buflen);

    uuid4_init();
    uuid4_generate(buf);

    printf("generated uuid4: %s\n", buf);

    if(strlen(buf) > 0)
    {
        ret = 0;
    }

    goto exit;

exit: {
    return ret;
}
}