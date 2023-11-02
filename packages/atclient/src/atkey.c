#include <stdlib.h>
#include <string.h>
#include "atclient/atkey.h"
#include "atclient/metadata.h"

#define ATKEY_GENERAL_BUFFER_SIZE 4096 // sufficient memory for keyName, namespace, sharedWith, and sharedBy strings

void atclient_atkey_init(atclient_atkey *atkey)
{
    memset(atkey, 0, sizeof(atclient_atkey));
    atclient_atstr_init(&(atkey->name), ATKEY_GENERAL_BUFFER_SIZE);
    atclient_atstr_init(&(atkey->namespacestr), ATKEY_GENERAL_BUFFER_SIZE);
    atclient_atstr_init(&(atkey->sharedby), ATKEY_GENERAL_BUFFER_SIZE);
    atclient_atstr_init(&(atkey->sharedwith), ATKEY_GENERAL_BUFFER_SIZE);

    atclient_atkey_metadata_init(&(atkey->metadata));
}

void atclient_atkey_free(atclient_atkey *atkey)
{
    free(atkey->name.str);
    free(atkey->namespacestr.str);
    free(atkey->sharedwith.str);
    free(atkey->sharedby.str);
}

int atclient_atkey_from_string(atclient_atkey *atkey, const char *atkeystr, const unsigned long atkeylen)
{
    // 6 scenarios:
    // 1. PublicKey:            "public:name.wavi@smoothalligator"
    //      name == "name"
    //      sharedby = "smoothalligator"
    //      sharedwith = NULL
    //      namespace = "wavi"
    //      type = "public"
    //      cached = false
    // 2. PublicKey (cached):   "cached:public:name.wavi@smoothalligator"
    //      name == "name"
    //      sharedby = "smoothalligator"
    //      sharedwith = NULL
    //      namespace = "wavi"
    //      type = "public"
    //      cached = true
    // 3. SharedKey:            "@foo:name.wavi@bar"
    //      name == "name"
    //      sharedby = "bar"
    //      sharedwith = "foo"
    //      namespace = "wavi"
    //      cached = false
    // 4. SharedKey (cached):   "cached:@bar:name.wavi@foo"
    //      name == "name"
    //      sharedby = "foo"
    //      sharedwith = "bar"
    //      namespace = "wavi"
    //      cached = true
    // 5. PrivateHiddenKey:     "_latestnotificationid.wavi@smoothalligator"
    //      name == "_latestnotificationid"
    //      sharedby = "smoothalligator"
    //      namespace = "wavi"
    //      cached = false
    // 6. SelfKey:              "name.wavi@smoothalligator"
    //      name == "name"
    //      sharedby = "smoothalligator"
    //      sharedwith = NULL
    //      namespace = "wavi"
    //      cached = false
    // more scenarios
    // 7. No Namespace, SelfKey:
    // "name@smoothalligator"
    //      name == "name"
    //      sharedby = "smoothalligator"
    //      sharedwith = NULL
    //      namespace = NULL
    //      cached = false

    return 1; // TODO: implement
}

int atclient_atkey_to_string(atclient_atkey atkey, char *atkeystr, unsigned long *atkeystrlen, unsigned long atkeystrolen)
{
    return 1; // TODO: implement
}

int atclient_atkey_create_publickey(atclient_atkey *atkey, const char *name, const char *sharedby, const char *namespacestr)
{
    return 1; // TODO: implement
}

int atclient_atkey_create_selfkey(atclient_atkey *atkey, const char *name, const char *sharedby, const char *namespacestr)
{
    return 1; // TODO: implement
}

int atclient_atkey_create_sharedkey(atclient_atkey *atkey, const char *name, const char *sharedby, const char *sharedwith, char *namespacestr)
{
    return 1; // TODO: implement
}