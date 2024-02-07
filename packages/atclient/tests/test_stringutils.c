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
    // todo

    str = "cached:public:publickey@bob";
    char **tokens; // array of char pointers
    unsigned long *tokensolen;
    ret = atclient_stringutils_split(str, strlen(str), ":", tokens, tokensolen);
    if(ret != 0)
    {
        atclient_atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atclient_stringutils_split: %d | %s\n", ret, str);
        ret = 1;
        goto exit;
    }

    ret = 0;

    goto exit;
exit:
{
    return ret;
}
}