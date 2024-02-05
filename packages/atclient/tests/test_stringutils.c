#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include "atclient/stringutils.h"
#include "atclient/atlogger.h"

#define TAG "test_stringutils"

int main()
{
    int ret = 1;

    const unsigned long outlen = 4096;
    char *out = (char *) malloc(sizeof(char) * outlen);
    memset(out, 0, sizeof(char) * outlen);
    unsigned long outolen = 0;

    const unsigned long tokenlen = 4096;
    const unsigned long tokenslen = 16;
    char **tokens = malloc(sizeof(char *) * tokenslen);
    memset(tokens, 0, sizeof(char *) * tokenslen);
    for(int i = 0; i < tokenslen; i++)
    {
        *(tokens + i) = malloc(sizeof(char) * tokenlen);
        memset(*(tokens + i), 0, sizeof(char) * tokenlen);
    }
    unsigned long tokensolen = 0;

    atclient_atlogger_set_logging_level(ATLOGGER_LOGGING_LEVEL_INFO);

    char *str = "@bob";

    int startswith;

    startswith = atclient_stringutils_starts_with(str, strlen(str), "@", strlen("@"));
    if(startswith != 1)
    {
        atclient_atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atclient_stringutils_starts_with: %d | %s starts with %s\n", ret, str, "@");
        ret = 1;
        goto exit;
    }

    startswith = atclient_stringutils_starts_with(str, strlen(str), "123", strlen("123"));
    if(startswith != 0)
    {
        atclient_atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atclient_stringutils_starts_with: %d | %s starts with %s\n", ret, str, "bob");
        ret = 1;
        goto exit;
    }

    int endswith;
    str = "root.atsign.org:64";

    endswith = atclient_stringutils_ends_with(str, strlen(str), "64", strlen("64"));
    if(endswith != 1)
    {
        atclient_atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atclient_stringutils_ends_with: %d | %s ends with %s\n", ret, str, "64");
        ret = 1;
        goto exit;
    }

    printf("a\n");
    endswith = atclient_stringutils_ends_with(str, strlen(str), "org", strlen("org"));
    if(endswith != 0)
    {
        atclient_atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atclient_stringutils_ends_with: %d | %s ends with %s\n", ret, str, "org");
        ret = 1;
        goto exit;
    }

    str = "  scan jeremy_0\n";
    const char *expectedresult  = "scan jeremy_0";
    ret = atclient_stringutils_trim_whitespace(str, strlen(str), out, outlen, &outolen);
    if(ret != 0)
    {
        atclient_atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atclient_stringutils_trim_whitespace: %d | %s\n", ret, str);
        ret = 1;
        goto exit;
    }

    if(strncmp(out, expectedresult, strlen(expectedresult)) != 0)
    {
        atclient_atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atclient_stringutils_trim_whitespace: \"%s\" != \"%s\"\n", str, expectedresult);
        ret = 1;
        goto exit;
    }

    str = "root.atsign.org:64";
    ret = atclient_stringutils_split(str, strlen(str), ":", tokens, tokenslen, &tokensolen, tokenlen);
    if(ret != 0)
    {
        atclient_atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atclient_stringutils_split: %d | %s\n", ret, str);
        ret = 1;
        goto exit;
    }

    if(tokensolen != 2)
    {
        atclient_atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atclient_stringutils_split: %lu != %d\n", tokensolen, 2);
        ret = 1;
        goto exit;
    }

    if(strncmp(*tokens, "root.atsign.org", strlen("root.atsign.org")) != 0)
    {
        atclient_atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atclient_stringutils_split: \"%s\" != \"%s\"\n", *tokens, "root.atsign.org");
        ret = 1;
        goto exit;
    }

    if(strncmp(*(tokens + 1), "64", strlen("64")) != 0)
    {
        atclient_atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atclient_stringutils_split: \"%s\" != \"%s\"\n", *(tokens + 1), "64");
        ret = 1;
        goto exit;
    }

    str = "cached:public:publickey@bob";
    for(int i = 0; i < tokenslen; i++)
    {
        memset(*(tokens + i), 0, sizeof(char) * tokenlen);
    }
    tokensolen = 0;

    ret = atclient_stringutils_split(str, strlen(str), ":", tokens, tokenslen, &tokensolen, tokenlen);
    if(ret != 0)
    {
        atclient_atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atclient_stringutils_split: %d | %s\n", ret, str);
        ret = 1;
        goto exit;
    }

    if(tokensolen != 3)
    {
        atclient_atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atclient_stringutils_split: %lu != %d\n", tokensolen, 4);
        ret = 1;
        goto exit;
    }

    if(strncmp(*(tokens + 0), "cached", strlen("cached")) != 0)
    {
        atclient_atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atclient_stringutils_split: \"%s\" != \"%s\"\n", *tokens, "cached");
        ret = 1;
        goto exit;
    }

    if(strncmp(*(tokens + 1), "public", strlen("public")) != 0)
    {
        atclient_atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atclient_stringutils_split: \"%s\" != \"%s\"\n", *(tokens + 1), "public");
        ret = 1;
        goto exit;
    }

    if(strncmp(*(tokens + 2), "publickey@bob", strlen("publickey@bob")) != 0)
    {
        atclient_atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atclient_stringutils_split: \"%s\" != \"%s\"\n", *(tokens + 2), "publickey@bob");
        ret = 1;
        goto exit;
    }

    ret = 0;

    goto exit;
exit:
{
    free(out);
    for(int i = 0; i < tokenslen; i++)
    {
        free(*(tokens + i));
    }
    free(tokens);
    return ret;
}
}