#include <stdio.h>
#include <string.h>
#include "atclient/atkey.h"
#include "atclient/atsign.h"
#include "atlogger/atlogger.h"

#define TAG "test_atkey_from_string"

// Test 1: public keys
// 1A: cached public key
// 1B: non-cached public key
// 1C. non-cached public key with namespace
// 1D. cached public key with namespace
// Test 2: shared keys
// 2A: non-cached shared key with namespace
// 2B: cached shared key without namespace
// 2C: non-cached shared key without namespace
// 2D: cached shared key with namespace
// Test 3: private hidden keys
// 3A: private hidden key
// Test 4: self keys
// 4A: self key with no namespace
// 4B: self key with namespace

static int test1a()
{
    atclient_atkey atkey1a;
    atclient_atkey_init(&atkey1a);

    const char *atkeystr = "cached:public:xxxxxxxxx@xxx";
    const unsigned long atkeystrlen = strlen(atkeystr);

    int ret = atclient_atkey_from_string(&atkey1a, atkeystr, atkeystrlen);
    if (ret != 0)
    {
        atclient_atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atclient_atkey_from_string failed\n");
        goto exit;
    }

    if (atkey1a.metadata.iscached != 1)
    {
        atclient_atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atkey.metadata.iscached is not 1\n");
        goto exit;
    }

    if (atkey1a.metadata.ispublic != 1)
    {
        atclient_atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atkey.metadata.ispublic is not 1, it is %d\n", atkey1a.metadata.ispublic);
        goto exit;
    }

    if (strncmp(atkey1a.name.str, "publickey", atkey1a.name.olen) != 0)
    {
        atclient_atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atkey.name is not publickey, it is \"%s\"\n", atkey1a.name.str);
        goto exit;
    }

    if (strncmp(atkey1a.sharedby.str, "@bob", atkey1a.sharedby.olen) != 0)
    {
        atclient_atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atkey.sharedby is not @bob, it is \"%s\"\n", atkey1a.sharedby.str);
        goto exit;
    }
    ret = 0;
    goto exit;
exit:
{
    return ret;
    atclient_atkey_free(&atkey1a);
}
}

static int test1b()
{
    int ret = 1;
    atclient_atkey atkey1b;
    atclient_atkey_init(&atkey1b);

    const char *atkeystr = "public:publickey@alice";
    const unsigned long atkeystrlen = strlen(atkeystr);

    ret = atclient_atkey_from_string(&atkey1b, atkeystr, atkeystrlen);
    if (ret != 0)
    {
        atclient_atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atclient_atkey_from_string failed\n");
        goto exit;
    }

    if (atkey1b.metadata.iscached != 0)
    {
        atclient_atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atkey.metadata.iscached is not 0\n");
        ret = 1;
        goto exit;
    }

    if (atkey1b.metadata.ispublic != 1)
    {
        atclient_atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atkey.metadata.ispublic is not 1, it is %d\n", atkey1b.metadata.ispublic);
        ret = 1;
        goto exit;
    }

    if (strncmp(atkey1b.name.str, "publickey", atkey1b.name.olen) != 0)
    {
        atclient_atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atkey.name is not publickey, it is \"%s\"\n", atkey1b.name.str);
        ret = 1;
        goto exit;
    }

    if (strncmp(atkey1b.sharedby.str, "@alice", atkey1b.sharedby.olen) != 0)
    {
        atclient_atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atkey.sharedby is not @alice, it is \"%s\"\n", atkey1b.sharedby.str);
        ret = 1;
        goto exit;
    }

    if(atkey1b.namespacestr.olen != 0)
    {
        atclient_atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atkey.namespacestr.olen is not 0, it is %lu\n", atkey1b.namespacestr.olen);
        ret = 1;
        goto exit;
    }

    if(atkey1b.sharedwith.olen != 0)
    {
        atclient_atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atkey.sharedwith.olen is not 0, it is %lu\n", atkey1b.sharedwith.olen);
        ret = 1;
        goto exit;
    }

    ret = 0;
    goto exit;

exit:{
    atclient_atkey_free(&atkey1b);
    return ret;
}
}

static int test2a()
{
    int ret = 1;
    atclient_atkey atkey2a;
    atclient_atkey_init(&atkey2a);

    const char *atkeystr = "@alice:name.wavi@bob";
    const unsigned long atkeystrlen = strlen(atkeystr);

    ret = atclient_atkey_from_string(&atkey2a, atkeystr, atkeystrlen);
    if (ret != 0)
    {
        atclient_atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atclient_atkey_from_string failed\n");
        goto exit;
    }

    if (atkey2a.metadata.iscached != 0)
    {
        atclient_atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atkey.metadata.iscached is not 0\n");
        ret = 1;
        goto exit;
    }

    if (atkey2a.metadata.ispublic != 0)
    {
        atclient_atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atkey.metadata.ispublic is not 0, it is %d\n", atkey2a.metadata.ispublic);
        ret = 1;
        goto exit;
    }

    if (strncmp(atkey2a.name.str, "name.wavi", atkey2a.name.olen) != 0)
    {
        atclient_atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atkey.name is not name.wavi, it is \"%s\"\n", atkey2a.name.str);
        ret = 1;
        goto exit;
    }

    if (strncmp(atkey2a.sharedby.str, "@bob", atkey2a.sharedby.olen) != 0)
    {
        atclient_atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atkey.sharedby is not @bob, it is \"%s\"\n", atkey2a.sharedby.str);
        ret = 1;
        goto exit;
    }

    if (strncmp(atkey2a.sharedwith.str, "@alice", atkey2a.sharedwith.olen) != 0)
    {
        atclient_atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atkey.sharedwith is not @alice, it is \"%s\"\n", atkey2a.sharedwith.str);
        ret = 1;
        goto exit;
    }

    if(strncmp(atkey2a.namespacestr.str, "wavi", atkey2a.namespacestr.olen) != 0)
    {
        atclient_atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atkey.namespacestr is not wavi, it is \"%s\"\n", atkey2a.namespacestr.str);
        ret = 1;
        goto exit;
    }

    ret = 0;
    goto exit;
exit:
{
    atclient_atkey_free(&atkey2a);
    return ret;
}
}

int main()
{
    int ret = 1;

    atclient_atlogger_set_logging_level(ATLOGGER_LOGGING_LEVEL_INFO);

    ret = test1a();
    if (ret != 0)
    {
        atclient_atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "test1a failed\n");
        return 1;
    }

    ret = test1b();
    if (ret != 0)
    {
        atclient_atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "test1b failed\n");
        return 1;
    }

    // test 2a. non-cached sharedkey with namespace
    ret = test2a();
    if (ret != 0)
    {
        atclient_atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "test2a failed\n");
        return 1;
    }

    ret = 0;
    goto exit;
exit:
{
    return ret;
}
}