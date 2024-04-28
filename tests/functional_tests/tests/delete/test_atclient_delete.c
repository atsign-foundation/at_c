
#include <atclient/atclient.h>
#include <atlogger/atlogger.h>

#define ROOT_HOST "root.atsign.org"
#define ROOT_PORT 64

#define TAG "test_atclient_delete"

int main()
{
    int ret = 1;

    atlogger_set_logging_level(ATLOGGER_LOGGING_LEVEL_ERROR);

    atclient atclient;
    atclient_init(&atclient);

    atclient_connection root_connection;
    atclient_connection_init(&root_connection);
    if ((ret = atclient_connection_connect(&root_connection, ROOT_HOST, ROOT_PORT)) != 0)
    {
        atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atclient_connection_connect: %d\n", ret);
    }

    return 0;
}