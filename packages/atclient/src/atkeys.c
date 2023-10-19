#include <stdlib.h>
#include <string.h>
#include "atclient/atkeys.h"

void atclient_atkeys_init(atclient_atkeys *atkeys)
{
    memset(atkeys, 0, sizeof(atclient_atkeys));
}
int atclient_atkeys_populate(atclient_atkeys *atkeys, atclient_atkeysfile *atkeysfile)
{
    int ret = 1;

    // TODO : implement

    goto exit;

exit: {
    return ret;
}
}
void atclient_atkeys_free(atclient_atkeys *atkeys)
{
    return ; // TODO: implement
}