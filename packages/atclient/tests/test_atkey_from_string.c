#include <stdio.h>
#include <string.h>
#include "atclient/atkey.h"
#include "atclient/atsign.h"
#include "atlogger/atlogger.h"

#define TAG "test_atkey_from_string"

int main()
{
    int ret = 1;

    atclient_atlogger_set_logging_level(ATLOGGER_LOGGING_LEVEL_INFO);

    atclient_atkey atkey1a;
    atclient_atkey_init(&atkey1a);

    atclient_atkey atkey1b;
    atclient_atkey_init(&atkey1b);

    atclient_atkey atkey2a;
    atclient_atkey_init(&atkey2a);

    const char *atkeystr = "cached:public:publickey@bob";
    const unsigned long atkeystrlen = strlen(atkeystr);

    ret = atclient_atkey_from_string(&atkey1a, atkeystr, atkeystrlen);
    if (ret != 0)
    {
        atclient_atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atclient_atkey_from_string failed\n");
        return 1;
    }

    if (atkey1a.metadata.iscached != 1)
    {
        atclient_atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atkey.metadata.iscached is not 1\n");
        ret = 1;
        goto exit;
    }

    if (atkey1a.metadata.ispublic != 1)
    {
        atclient_atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atkey.metadata.ispublic is not 1, it is %d\n", atkey1a.metadata.ispublic);
        ret = 1;
        goto exit;
    }

    if (strncmp(atkey1a.name.str, "publickey", atkey1a.name.olen) != 0)
    {
        atclient_atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atkey.name is not publickey, it is \"%s\"\n", atkey1a.name.str);
        ret = 1;
        goto exit;
    }

    if (strncmp(atkey1a.sharedby.str, "@bob", atkey1a.sharedby.olen) != 0)
    {
        atclient_atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atkey.sharedby is not @bob, it is \"%s\"\n", atkey1a.sharedby.str);
        ret = 1;
        goto exit;
    }

    // test 1b. non-cached publickey
    const char *atkeystr1b = "public:publickey@colin";
    const unsigned long atkeystrlen1b = strlen(atkeystr1b);

    ret = atclient_atkey_from_string(&atkey1b, atkeystr1b, atkeystrlen1b);
    if (ret != 0)
    {
        atclient_atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atclient_atkey_from_string failed\n");
        return 1;
    }

    if (atkey1b.metadata.iscached != 0)
    {
        atclient_atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atkey1b.metadata.iscached is not 0\n");
        ret = 1;
        goto exit;
    }

    if (atkey1b.metadata.ispublic != 1)
    {
        atclient_atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atkey1b.metadata.ispublic is not 1, it is %d\n", atkey1b.metadata.ispublic);
        ret = 1;
        goto exit;
    }

    if (strncmp(atkey1b.name.str, "publickey", atkey1b.name.olen) != 0)
    {
        atclient_atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atkey1b.name is not publickey, it is \"%s\"\n", atkey1b.name.str);
        ret = 1;
        goto exit;
    }

    if (strncmp(atkey1b.sharedby.str, "@colin", atkey1b.sharedby.olen) != 0)
    {
        atclient_atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atkey1b.sharedby is not @colin, it is \"%s\"\n", atkey1b.sharedby.str);
        ret = 1;
        goto exit;
    }

    if(atkey1b.namespacestr.olen != 0)
    {
        atclient_atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atkey1b.namespacestr.olen is not 0, it is %lu\n", atkey1b.namespacestr.olen);
        ret = 1;
        goto exit;
    }

    if(atkey1b.sharedwith.olen != 0)
    {
        atclient_atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atkey1b.sharedwith.olen is not 0, it is %lu\n", atkey1b.sharedwith.olen);
        ret = 1;
        goto exit;
    }

    // test 2a. non-cached sharedkey with namespace
    const char *atkeystr2a = "@xavier:name.wavi@jeremy";
    const unsigned long atkeystrlen2a = strlen(atkeystr2a);

    ret = atclient_atkey_from_string(&atkey2a, atkeystr2a, atkeystrlen2a);
    if (ret != 0)
    {
        atclient_atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atclient_atkey_from_string failed with atkey \"%s\"\n", atkeystr2a);
        return 1;
    }

    if (atkey2a.metadata.iscached != 0)
    {
        atclient_atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atkey2a.metadata.iscached is not 0\n");
        ret = 1;
        goto exit;
    }

    if (atkey2a.metadata.ispublic != 0)
    {
        atclient_atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atkey2a.metadata.ispublic is not 0, it is %d\n", atkey2a.metadata.ispublic);
        ret = 1;
        goto exit;
    }

    if (strncmp(atkey2a.name.str, "name", atkey2a.name.olen) != 0)
    {
        atclient_atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atkey2a.name is not name, it is \"%s\"\n", atkey2a.name.str);
        ret = 1;
        goto exit;
    }

    if (strncmp(atkey2a.sharedby.str, "@jeremy", atkey2a.sharedby.olen) != 0)
    {
        atclient_atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atkey2a.sharedby is not @xavier, it is \"%s\"\n", atkey2a.sharedby.str);
        ret = 1;
        goto exit;
    }

    if (strncmp(atkey2a.sharedwith.str, "@xavier", atkey2a.sharedwith.olen) != 0)
    {
        atclient_atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atkey2a.sharedwith is not @jeremy, it is \"%s\"\n", atkey2a.sharedwith.str);
        ret = 1;
        goto exit;
    }

    if (strncmp(atkey2a.namespacestr.str, "wavi", atkey2a.namespacestr.olen) != 0)
    {
        atclient_atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atkey2a.namespacestr is not wavi, it is \"%s\"\n", atkey2a.namespacestr.str);
        ret = 1;
        goto exit;
    }


    ret = 0;
    goto exit;
exit:
{
    atclient_atkey_free(&atkey1a);
    return ret;
}
}