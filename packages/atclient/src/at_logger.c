#include <stdio.h>
#include "atclient/at_logger.h"

static void printx(const unsigned char *bytes, size_t byteslen) {
    for (size_t i = 0; i < byteslen; i++) {
        printf("%02x ", bytes[i]);
    }
    printf("\n");
}

int atlogger_log(const char *title, const char *message) {
    printf("%s | %s:\n", title, message);
    return 0;
}

int atlogger_logx(const char *title, const unsigned char *bytes, size_t byteslen) {
    printf("%s | ", title);
    printx(bytes, byteslen);
    return 0;
}
