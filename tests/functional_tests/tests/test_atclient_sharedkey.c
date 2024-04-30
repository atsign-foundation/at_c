#include <atclient/atclient.h>
#include <atclient/constants.h>
#include <atlogger/atlogger.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "functional_tests/config.h"

#define TAG "test_atclient_delete"

#define ATKEY_KEY "test"
#define ATKEY_NAMESPACE "functional_tests"
#define ATKEY_SHAREDBY FIRST_ATSIGN
#define ATKEY_SHAREDWITH SECOND_ATSIGN
#define ATKEY_VALUE "test 123"

static int set_up(atclient *atclient, char *atsign);
static int test_1_put(atclient *atclient);
static int test_1_get(atclient *atclient);
static int test_1_delete(atclient *atclient);
static int tear_down(atclient *atclient);

int main()
{
    int ret = 1;

    atlogger_set_logging_level(ATLOGGER_LOGGING_LEVEL_DEBUG);

    char *atsign1 = FIRST_ATSIGN;
    const size_t atsign1len = strlen(atsign1);

    char *atsign2 = SECOND_ATSIGN;
    const size_t atsign2len = strlen(atsign2);

    atclient atclient;
    atclient_init(&atclient);

    if((ret = set_up(&atclient, atsign1)) != 0)
    {
        atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "set_up: %d\n", ret);
        goto exit;
    }

    if((ret = test_1_put(&atclient)) != 0)
    {
        atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "test_1_put: %d\n", ret);
        goto exit;
    }

    if((ret = tear_down(&atclient)) != 0)
    {
        atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "tear_down: %d\n", ret);
        goto exit;
    }

exit: {
    atclient_free(&atclient);
    return ret;
}
}

static int set_up(atclient *atclient, char *atsign)
{
    int ret = 1;

    const size_t atkeysfilepathsize = 256;
    char atkeysfilepath[atkeysfilepathsize];
    memset(atkeysfilepath, 0, sizeof(char) * atkeysfilepathsize);
    size_t atkeysfilepathlen = 0;

    atclient_connection root_connection;
    atclient_connection_init(&root_connection);

    atclient_atkeys atkeys;
    atclient_atkeys_init(&atkeys);

    if((ret = get_atkeys_path(atsign, strlen(atsign), atkeysfilepath, atkeysfilepathsize, &atkeysfilepathlen)))
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

    if ((ret = atclient_pkam_authenticate(atclient, &root_connection, &atkeys, atsign)) != 0)
    {
        atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atclient_pkam_authenticate: %d\n", ret);
        goto exit;
    }
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_INFO, "pkam authenticated\n");

    ret = 0;
    goto exit;

exit: {
    atclient_connection_free(&root_connection);
    return ret;
}
}

static int test_1_put(atclient *atclient)
{
    int ret = 1;

    atclient_atkey atkey;
    atclient_atkey_init(&atkey);

    if ((ret = atclient_atkey_create_sharedkey(&atkey, ATKEY_KEY, strlen(ATKEY_KEY), ATKEY_SHAREDBY, strlen(ATKEY_SHAREDBY), ATKEY_SHAREDWITH, strlen(ATKEY_SHAREDWITH), ATKEY_NAMESPACE, strlen(ATKEY_NAMESPACE))) != 0)
    {
        atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atclient_atkey_create_sharedkey: %d\n", ret);
        goto exit;
    }
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_INFO, "atkey created for deletion\n");

    atclient_atkey_metadata_set_ttl(&atkey.metadata, 60*1000*1); // 1 minute

    if((ret = atclient_put(atclient, &atkey, ATKEY_VALUE, strlen(ATKEY_VALUE), NULL)) != 0)
    {
        atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atclient_put: %d\n", ret);
        goto exit;
    }

    ret = 0;
    goto exit;
exit: {
    atclient_atkey_free(&atkey);
    return ret;
}
}

static int test_1_get(atclient *atclient)
{
    int ret = 1;
    ret = 0;
    goto exit;
exit: {
    return ret;
}
}

static int test_1_delete(atclient *atclient)
{
    int ret = 1;
    ret = 0;
    goto exit;
exit: {
    return ret;
}
}

static int tear_down(atclient *atclient)
{
    int ret = 1;

    char atkeystrtemp[ATCLIENT_ATKEY_FULL_LEN];

    atclient_atkey atkeyforme;
    atclient_atkey_init(&atkeyforme);

    atclient_atkey atkeyforthem;
    atclient_atkey_init(&atkeyforthem);

    // memset(atkeystrtemp, 0, sizeof(char) * ATCLIENT_ATKEY_FULL_LEN);
    // snprintf(atkeystrtemp, ATCLIENT_ATKEY_FULL_LEN, "shared_key.%s%s", ATKEY_SHAREDWITH + 1, ATKEY_SHAREDBY);
    // if((ret = atclient_atkey_from_string(&atkeyforme, atkeystrtemp, strlen(atkeystrtemp))) != 0)
    // {
    //     atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atclient_atkey_from_string: %d\n", ret);
    //     goto exit;
    // }

    // memset(atkeystrtemp, 0, sizeof(char) * ATCLIENT_ATKEY_FULL_LEN);
    // snprintf(atkeystrtemp, ATCLIENT_ATKEY_FULL_LEN, "%s:shared_key%s", ATKEY_SHAREDWITH, ATKEY_SHAREDBY);
    // if((ret = atclient_atkey_from_string(&atkeyforthem, atkeystrtemp, strlen(atkeystrtemp))) != 0)
    // {
    //     atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atclient_atkey_from_string: %d\n", ret);
    //     goto exit;
    // }

    // if((ret = atclient_delete(atclient, &atkeyforme)) != 0)
    // {
    //     atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atclient_delete: %d\n", ret);
    //     goto exit;
    // }

    // if((ret = atclient_delete(atclient, &atkeyforthem)) != 0)
    // {
    //     atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atclient_delete: %d\n", ret);
    //     goto exit;
    // }

    ret = 0;
    goto exit;

exit: {
    atclient_atkey_free(&atkeyforme);
    atclient_atkey_free(&atkeyforthem);
    return ret;
}
}
