#include <stdio.h>
#include <atclient/atclient.h>
#include <atlogger/atlogger.h>

void app_main(void) {
    atlogger_set_logging_level(ATLOGGER_LOGGING_LEVEL_DEBUG);

    atclient atclient;
    atclient_init(&atclient);
}