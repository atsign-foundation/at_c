#include <stdio.h>
#include <string.h>
#include <atclient/atclient.h>
#include <atchops/uuid.h>

void app_main(void) {
    printf("Hello, World!\n");

    atchops_uuid_init();

    char my_str[90];
    memset(my_str, 0, sizeof(char) * 90);

    atchops_uuid_generate(my_str, 90);

    printf("UUID: %s\n", my_str);
}