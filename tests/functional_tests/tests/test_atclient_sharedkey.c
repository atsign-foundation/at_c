#include <atclient/atclient.h>
#include <atclient/constants.h>
#include <atlogger/atlogger.h>
#include <stdlib.h>
#include <string.h>
#include "config.h"

#define TAG "test_atclient_delete"

#define ATKEY_KEY "test"
#define ATKEY_NAMESPACE "functional_tests"
#define ATKEY_SHAREDBY FIRST_ATSIGN
#define ATKEY_SHAREDWITH SECOND_ATSIGN

static int set_up(atclient *atclient_ctx, char *atsign, const size_t atsignlen);
static int test_1_put(atclient *atclient_ctx);
static int test_1_get(atclient *atclient_ctx);
static int test_1_delete(atclient *atclient_ctx);
static int tear_down();

int main()
{
    int ret = 1;

    char *atsign1 = FIRST_ATSIGN;
    const size_t atsign1len = strlen(atsign1);

    char *atsign2 = SECOND_ATSIGN;
    const size_t atsign2len = strlen(atsign2);

    atclient atclient;
    atclientt_init(&atclient);

    if((ret = set_up(&atclient, atsign1, atsign1len)) != 0)
    {
        atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "set_up: %d\n", ret);
        goto exit;
    }

    if((ret = tear_down()) != 0)
    {
        atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "tear_down: %d\n", ret);
        goto exit;
    }

    atclient_atkey atkey;
    atclient_atkey_init(&atkey);

    const size_t atkeystrsize = ATCLIENT_ATKEY_FULL_LEN;
    char atkeystr[ATCLIENT_ATKEY_FULL_LEN];
    memset(atkeystr, 0, sizeof(char) * atkeystrsize);
    size_t atkeystrlen = 0;

    if ((ret = atclient_atkey_create_selfkey(&atkey, ATKEY_KEY, strlen(ATKEY_KEY), ATKEY_SHAREDBY, strlen(ATKEY_SHAREDBY), ATKEY_NAMESPACE, strlen(ATKEY_NAMESPACE))) != 0) 
    {
        atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atclient_atkey_create_selfkey: %d\n", ret);
        goto exit;
    }
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_INFO, "atkey created for deletion\n");

    if((ret = atclient_delete(&atclient, &atkey)) != 0)
    {
        atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atclient_delete: %d\n", ret);
        goto exit;
    }
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_INFO, "atkey deleted\n");

exit: {
    atclient_free(&atclient);
    return ret;
}
}

static int set_up(atclient *atclient_ctx, char *sharedby_atsign, const size_t sharedby_atsignlen)
{
    int ret = 1;

    atlogger_set_logging_level(ATLOGGER_LOGGING_LEVEL_DEBUG);

    const size_t atkeysfilepathsize = 256;
    char atkeysfilepath[atkeysfilepathsize];
    memset(atkeysfilepath, 0, sizeof(char) * atkeysfilepathsize);
    size_t atkeysfilepathlen = 0;

    atclient_connection root_connection;
    atclient_connection_init(&root_connection);

    atclient_atkeys atkeys;
    atclient_atkeys_init(&atkeys);

    if((ret = get_atkeys_path(sharedby_atsign, sharedby_atsignlen, atkeysfilepath, atkeysfilepathsize, &atkeysfilepathlen)))
    {
        atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "get_atkeys_path: %d\n", ret);
        goto exit;
    }
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_INFO, "atkeysfilepath: \"%s\"\n", atkeysfilepath);

    if ((ret = atclient_atkeys_populate_from_path(&atkeys, atkeysfilepath)))
    {
        atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atclient_atkeys_populate_from_path: %d\n", ret);
        goto exit;
    }
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_INFO, "atkeys populated\n");

    if ((ret = atclient_connection_connect(&root_connection, ROOT_HOST, ROOT_PORT)) != 0)
    {
        atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atclient_connection_connect: %d\n", ret);
        goto exit;
    }
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_INFO, "root connection established\n");

    if ((ret = atclient_pkam_authenticate(atclient_ctx, &root_connection, atkeys, sharedby_atsign, sharedby_atsignlen)) != 0)
    {
        atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atclient_pkam_authenticate: %d\n", ret);
        goto exit;
    }
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_INFO, "pkam authenticated\n");

    ret = 0;
    goto exit;

exit: {
    atclient_connection_free(&root_connection);
    atclient_atkeys_free(&atkeys);
    return ret;
}
}

static int test_1_put(atclient *atclient_ctx)
{
    int ret = 1;
    ret = 0;
    goto exit;
exit: {
    return ret;
}
}

static int test_1_get(atclient *atclient_ctx)
{
    int ret = 1;
    ret = 0;
    goto exit;
exit: {
    return ret;
}
}

static int test_1_delete(atclient *atclient_ctx)
{
    int ret = 1;
    ret = 0;
    goto exit;
exit: {
    return ret;
}
}

static int tear_down()
{
    int ret = 1;

    ret = 0;
    goto exit;

exit: {
    return ret;
}
}
