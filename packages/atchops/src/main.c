#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include "atchops/sha.h"
#include <mbedtls/md.h>

int main(int argc, char **argv)
{
    atchops_md_type md_type = ATCHOPS_MD_SHA256;
    unsigned char a = mbedtls_md_get_size(mbedtls_md_info_from_type(md_type));

    printf("a: %d\n", a);
    return 0;
}