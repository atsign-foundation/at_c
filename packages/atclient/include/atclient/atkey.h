#ifndef ATKEY_H
#define ATKEY_H

typedef enum atclient_atkey_type
{
    PUBLICKEY = 0,
    SELFKEY,
    SHAREDKEY,
} atclient_atkey_type;

typedef struct atclient_atkey
{
    unsigned long namelen;
    char *namestr;
    unsigned long nameolen;

    unsigned long namespacelen;
    char *namespacestr;
    unsigned long namespaceolen;

    unsigned long sharedwithlen;
    char *sharedwithstr;
    unsigned long sharedwitholen;

    unsigned long sharedbylen;
    char *sharedbystr;
    unsigned long sharedbyolen;

    atclient_atkey_type atkeytype;

} atclient_atkey;

void atclient_atkey_init(atclient_atkey *atkey);
void atclient_atkey_free(atclient_atkey *atkey);
int atclient_atkey_create_publickey(atclient_atkey *atkey, const char *name, const char *sharedby, const char *namespacestr);
int atclient_atkey_create_selfkey(atclient_atkey *atkey, char *name, char *sharedby, char *namespacestr);
int atclient_atkey_create_sharedkey(atclient_atkey *atkey, char *name, char *sharedby, char *namespacestr, char *sharedwith);
int atclient_atkey_create_from_string(atclient_atkey *atkey, const char *atkeystr);
int atclient_atkey_to_string(atclient_atkey atkey, char *atkeystr, unsigned long *atkeystrlen, unsigned long atkeystrolen);

#endif