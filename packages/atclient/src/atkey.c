#include <stdlib.h>
#include <string.h>
#include "atclient/atkey.h"
#include "atclient/metadata.h"

#define ATKEY_GENERAL_BUFFER_SIZE 4096 // sufficient memory for keyName, namespace, sharedWith, and sharedBy strings

void atclient_atkey_init(atclient_atkey *atkey)
{
    memset(atkey, 0, sizeof(atclient_atkey));
    atkey->namelen = ATKEY_GENERAL_BUFFER_SIZE;
    atkey->namestr = (char *)malloc(sizeof(char) * atkey->namelen);
    atkey->nameolen = 0;

    atkey->namespacelen = ATKEY_GENERAL_BUFFER_SIZE;
    atkey->namespacestr = (char *)malloc(sizeof(char) * atkey->namespacelen);
    atkey->namespaceolen = 0;

    atkey->sharedwithlen = ATKEY_GENERAL_BUFFER_SIZE;
    atkey->sharedwithstr = (char *)malloc(sizeof(char) * atkey->sharedwithlen);
    atkey->sharedwitholen = 0;

    atkey->sharedbylen = ATKEY_GENERAL_BUFFER_SIZE;
    atkey->sharedbystr = (char *)malloc(sizeof(char) * atkey->sharedbylen);
    atkey->sharedbyolen = 0;

    atclient_atkey_metadata_init(&(atkey->metadata));
}

void atclient_atkey_free(atclient_atkey *atkey)
{
    free(atkey->namestr);
    free(atkey->namespacestr);
    free(atkey->sharedwithstr);
    free(atkey->sharedbystr);
}

int atclient_atkey_create_from_string(atclient_atkey *atkey, const char *atkeystr)
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