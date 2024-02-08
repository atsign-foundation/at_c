#include <stdio.h>
#include <string.h>
#include "atclient/atkey.h"

int main()
{
    int ret = 1;

    ret = 0;
    goto exit;

    const char *atkeystr = "cached:public:publickey@bob";
    const unsigned long atkeystrlen = strlen(atkeystr);

    atclient_atkey atkey;
    atclient_atkey_init(&atkey);


    ret = atclient_atkey_from_string(&atkey, atkeystr, atkeystrlen);
    if (ret != 0)
    {
        printf("atclient_atkey_from_string failed\n");
        return 1;
    }

    if (atkey.metadata.iscached != 1)
    {
        printf("atkey.metadata.iscached is not 1\n");
        ret = 1;
        goto exit;
    }

    if (atkey.metadata.ispublic != 1)
    {
        printf("atkey.metadata.ispublic is not 1\n");
        ret = 1;
        goto exit;
    }

    if (strncmp(atkey.name.str, "publickey", atkey.name.olen) != 0)
    {
        printf("atkey.name is not publickey\n");
        ret = 1;
        goto exit;
    }

    if (strncmp(atkey.sharedby.str, "bob", atkey.sharedby.olen) != 0)
    {
        printf("atkey.sharedby is not bob\n");
        ret = 1;
        goto exit;
    }

    goto exit;
exit:
{
    atclient_atkey_free(&atkey);
    return ret;
}
}