#include <stdlib.h>
#include <string.h>
#include "atclient/atkey.h"
#include "atlogger/atlogger.h"
#include "atclient/metadata.h"
#include "atclient/atstr.h"
#include "atclient/stringutils.h"

#define TAG "atkey"

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
    int ret = 1;
    const unsigned long tokenlen = ATKEY_GENERAL_BUFFER_SIZE;
    const unsigned long tokenslen = 16;
    char *tokens[tokenslen];
    for(unsigned long i = 0; i < tokenslen; i++)
    {
        tokens[i] = calloc(tokenlen, sizeof(char));
    }
    unsigned long tokensolen = 0;
    // split on ':'
    // ret = atclient_stringutils_split(atkeystr, atkeylen, ":", tokens, tokenslen, &tokensolen, tokenlen);
    // if(ret != 0)
    // {
    //     atclient_atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atclient_atstr_split failed\n");
    //     goto exit;
    // }
    // if(tokens[0] == NULL)
    // {
    //     atclient_atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "tokens[0] is NULL\n");
    //     ret = 1;
    //     goto exit;
    // }
    // // check if cached
    // if(strcmp(*(tokens + 0), "cached") == 0)
    // {
    //     atkey->metadata.iscached = 1;
    // }

    // // shift tokens array to the left
    // for(unsigned long i = 0; i < tokenslen - 1; i++)
    // {
    //     tokens[i] = tokens[i + 1];
    // }
    // tokens[tokenslen - 1] = NULL;

    // char *currenttoken = *(tokens + 0);
    // unsigned long currenttokenlen = strlen(currenttoken);

    // if(atclient_stringutils_starts_with(currenttoken, currenttokenlen, "public", strlen("public")) == 1)
    // {
    //     // it is a public key
    //     atkey->metadata.ispublic = 1;
    //     atkey->atkeytype = ATCLIENT_ATKEY_TYPE_PUBLICKEY;
    //     // shift tokens array to the left
    //     for(unsigned long i = 0; i < tokenslen - 1; i++)
    //     {
    //         tokens[i] = tokens[i + 1];
    //     }
    //     tokens[tokenslen - 1] = NULL;
    // }
    // else if(atclient_stringutils_starts_with(currenttoken, currenttokenlen, "@", strlen("@")) == 1)
    // {
    //     // it is a shared key
    //     atkey->atkeytype = ATCLIENT_ATKEY_TYPE_SHAREDKEY;
    //     // set sharedwith
    //     ret = atclient_atstr_set_literal(&(atkey->sharedwith), currenttoken, currenttokenlen);
    //     if(ret != 0)
    //     {
    //         atclient_atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atclient_atstr_set_literal failed\n");
    //         goto exit;
    //     }
    //     // shift tokens array to the left
    //     for(unsigned long i = 0; i < tokenslen - 1; i++)
    //     {
    //         tokens[i] = tokens[i + 1];
    //     }
    // }
    // else if(atclient_stringutils_starts_with(currenttoken, currenttokenlen, "_", strlen("_")) == 1)
    // {
    //     // it is a private hidden key
    //     atkey->atkeytype = ATCLIENT_ATKEY_TYPE_PRIVATEHIDDENKEY;
    // }
    // else
    // {
    //     // it is a self key
    //     atkey->atkeytype = ATCLIENT_ATKEY_TYPE_SELFKEY;
    // }
    // // set atkey->name
    // currenttoken = *(tokens + 0);
    // currenttokenlen = strlen(currenttoken);
exit:
{
    // for(unsigned long i = 0; i < tokenslen; i++)
    // {
    //     free(tokens[i]);
    // }
    return ret;
}
}

int atclient_atkey_from_atstr(atclient_atkey *atkey, const atclient_atstr atstr)
{
    return atclient_atkey_from_string(atkey, atstr.str, atstr.olen);
}

int atclient_atkey_to_string(const atclient_atkey atkey, char *atkeystr, unsigned long *atkeystrlen, unsigned long *atkeystrolen)
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