#include <atclient/connection.h>
#include <atlogger/atlogger.h>
#include <functional_tests/helpers.h>

#define TAG "test_atclient_connection"

#define ROOT_HOST "root.atsign.org" 
#define ROOT_PORT 64

static int test_1_initialize(atclient_connection *conn);
static int test_2_connect(atclient_connection *conn);
static int test_3_is_connected(atclient_connection *conn);
static int test_4_send(atclient_connection *conn);
static int test_5_disconnect(atclient_connection *conn);
static int test_6_send(atclient_connection *conn); // should fail, a failuer to send will return 0
static int test_7_free(atclient_connection *conn);

int main(int argc, char *argv[])
{
    int ret = 1;

    atlogger_set_logging_level(ATLOGGER_LOGGING_LEVEL_DEBUG);

    atclient_connection root_conn;

    if ((ret = test_1_initialize(&root_conn)) != 0)
    {
        atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "test_1_initialize: %d\n", ret);
        goto exit;
    }

    if((ret = test_2_connect(&root_conn)) != 0)
    {
        atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "test_2_connect: %d\n", ret);
        goto exit;
    }

    if((ret = test_3_is_connected(&root_conn)) != 0)
    {
        atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "test_3_is_connected: %d\n", ret);
        goto exit;
    }

    ret = 0;
    goto exit;
exit: {
    return ret;
}
}

static int test_1_initialize(atclient_connection *conn)
{
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_INFO, "test_1_initialize Begin\n");

    int ret = 1;

    atclient_connection_init(conn);

    if(!conn->should_be_initialized)
    {
        atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "ctx->should_be_initialized should be true, but is false\n");
        ret = 1;
        goto exit;
    }

    if(conn->should_be_connected)
    {
        atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "ctx->should_be_connected should be false, but is true.\n");
        ret = 1;
        goto exit;
    }

    ret = 0;
    goto exit;
exit: {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_INFO, "test_1_initialize End: %d\n", ret);
    return ret;
}
}

static int test_2_connect(atclient_connection *conn)
{
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_INFO, "test_2_connect Begin\n");

    int ret = 1;

    ret = atclient_connection_connect(conn, ROOT_HOST, ROOT_PORT);
    if (ret != 0)
    {
        atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "Failed to connect: %d\n", ret);
        goto exit;
    }

    if(!conn->should_be_connected)
    {
        atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "ctx->should_be_connected should be true, but is false\n");
        ret = 1;
        goto exit;
    }

    ret = 0;
    goto exit;
exit: {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_INFO, "test_2_connect End: %d\n", ret);
    return ret;
}
}

static int test_3_is_connected(atclient_connection *conn)
{
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_INFO, "test_3_is_connected Begin\n");

    int ret = 1;

    ret = atclient_connection_is_connected(conn);
    if (ret != 1)
    {
        atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "Failed to connect: %d\n", ret);
        goto exit;
    }

    ret = 0;
    goto exit;
exit: {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_INFO, "test_3_is_connected End: %d\n", ret);
    return ret;
}
}