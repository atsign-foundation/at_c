#include "functional_tests/config.h"
#include <stddef.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>

int main()
{
    const size_t pathsize = 256;
    char path [pathsize];
    memset(path, 0, sizeof(char) * pathsize);
    size_t pathlen;

    get_atkeys_path(FIRST_ATSIGN, strlen(FIRST_ATSIGN), path, pathsize, &pathlen);

    printf("Path: %s\n", path); // Path: keys/@12alpaca_key.atKeys
    return 0;
}
