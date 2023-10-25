#include <stdlib.h>
#include <string.h>
#include "atclient/atkey.h"

void atclient_atkey_init(atclient_atkey *atkey)
{
    memset(atkey, 0, sizeof(atclient_atkey));
    return; // TODO: implement
}

void atclient_atkey_free(atclient_atkey *atkey)
{
    return; // TODO: implement
}

int atclient_atkey_create_publickey(atclient_atkey *atkey, const char *name, const char *sharedby, const char *namespacestr)
{
    return 1; // TODO: implement
}

int atclient_atkey_create_selfkey(atclient_atkey *atkey, char *name, char *sharedby, char *namespacestr)
{
    return 1; // TODO: implement
}

int atclient_atkey_create_sharedkey(atclient_atkey *atkey, char *name, char *sharedby, char *namespacestr, char *sharedwith)
{
    return 1; // TODO: implement
}

int atclient_atkey_create_from_string(atclient_atkey *atkey, const char *atkeystr)
{
    return 1; // TODO: implement
}

int atclient_atkey_to_string(atclient_atkey atkey, char *atkeystr, unsigned long *atkeystrlen, unsigned long atkeystrolen)
{
    return 1; // TODO: implement
}
