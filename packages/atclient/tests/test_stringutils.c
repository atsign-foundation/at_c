#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include "atclient/stringutils.h"
#include "atlogger/atlogger.h"

#define TAG "test_stringutils"

int main()
{
    int ret = 1;

    atclient_atlogger_set_logging_level(ATLOGGER_LOGGING_LEVEL_INFO);

    const unsigned long outlen = 4096;
    char *out = (char *) malloc(sizeof(char) * outlen);
    memset(out, 0, sizeof(char) * outlen);
    unsigned long outolen = 0;

    const unsigned long stringlen = 4096;
    char *string = (char *) malloc(sizeof(char) * stringlen);
    memset(string, 0, sizeof(char) * stringlen);
    strcpy(string, "@bob");

    const unsigned long tokenslen = 8;
    char **tokens = malloc(sizeof(char *) * tokenslen); // array of char pointers
    memset(tokens, 0, sizeof(char *) * tokenslen); // set all pointers to NULL (0
    unsigned long tokensolen = 0;

    int startswith;

    // 1a. @bob starts with @
    startswith = atclient_stringutils_starts_with(string, strlen(string), "@", strlen("@"));
    if(startswith != 1)
    {
        atclient_atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atclient_stringutils_starts_with: %d | %s starts with %s\n", ret, string, "@");
        ret = 1;
        goto exit;
    }

    // 1b. @bob does not start with 123
    startswith = atclient_stringutils_starts_with(string, strlen(string), "123", strlen("123"));
    if(startswith != 0)
    {
        atclient_atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atclient_stringutils_starts_with: %d | %s starts with %s\n", ret, string, "bob");
        ret = 1;
        goto exit;
    }


    int endswith;
    strcpy(string, "root.atsign.org:64");
    // 2a. root.atsign.org:64 ends with 64
    endswith = atclient_stringutils_ends_with(string, strlen(string), "64", strlen("64"));
    if(endswith != 1)
    {
        atclient_atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atclient_stringutils_ends_with: %d | %s ends with %s\n", ret, string, "64");
        ret = 1;
        goto exit;
    }

    // 2b. root.atsign.org:64 does not end with org
    endswith = atclient_stringutils_ends_with(string, strlen(string), "org", strlen("org"));
    if(endswith != 0)
    {
        atclient_atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atclient_stringutils_ends_with: %d | %s ends with %s\n", ret, string, "org");
        ret = 1;
        goto exit;
    }

    // 3. trim whitespace and newline
    strcpy(string, "   scan jeremy_0\n ");
    const char *expectedresult  = "scan jeremy_0";
    ret = atclient_stringutils_trim_whitespace(string, strlen(string), out, outlen, &outolen);
    if(ret != 0)
    {
        atclient_atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atclient_stringutils_trim_whitespace: %d | %s\n", ret, string);
        ret = 1;
        goto exit;
    }

    if(strncmp(out, expectedresult, strlen(expectedresult)) != 0)
    {
        atclient_atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atclient_stringutils_trim_whitespace: \"%s\" != \"%s\"\n", string, expectedresult);
        ret = 1;
        goto exit;
    }

    // 4a. split root.atsign.org:64 into root.atsign.org and 64
    strcpy(string, "root.atsign.org:64");
    // ret = atclient_stringutils_split(string, strlen(string), ":", tokens, &tokensolen);
    // if(ret != 0)
    // {
    //     atclient_atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atclient_stringutils_split: %d | %s\n", ret, string);
    //     ret = 1;
    //     goto exit;
    // }
    // if(tokensolen != 2)
    // {
    //     atclient_atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atclient_stringutils_split: %lu != 2\n", tokensolen);
    //     ret = 1;
    //     goto exit;
    // }
    // if(strncmp(tokens[0], "root.atsign.org", strlen("root.atsign.org")) != 0)
    // {
    //     atclient_atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atclient_stringutils_split: %s != root.atsign.org\n", tokens[0]);
    //     ret = 1;
    //     goto exit;
    // }
    // if(strncmp(tokens[1], "64", strlen("64")) != 0)
    // {
    //     atclient_atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atclient_stringutils_split: %s != 64\n", tokens[1]);
    //     ret = 1;
    //     goto exit;
    // }

    // 4b. split cached:public:publickey@bob into cached, public, publickey@bob
    // memset(tokens, 0, sizeof(char *) * 8);
    // tokensolen = 0;
    // memset(string, 0, sizeof(char) * stringlen);
    // strcpy(string, "cached:public:publickey@bob");
    // ret = atclient_stringutils_split(string, strlen(string), ":", tokens, &tokensolen);
    // if(ret != 0)
    // {
    //     atclient_atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atclient_stringutils_split: %d | %s\n", ret, string);
    //     ret = 1;
    //     goto exit;
    // }
    // if(tokensolen != 3)
    // {
    //     atclient_atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atclient_stringutils_split: %lu != 3\n", tokensolen);
    //     ret = 1;
    //     goto exit;
    // }
    // if(strncmp(tokens[0], "cached", strlen("cached")) != 0)
    // {
    //     atclient_atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atclient_stringutils_split: %s != cached\n", tokens[0]);
    //     ret = 1;
    //     goto exit;
    // }
    // if(strncmp(tokens[1], "public", strlen("public")) != 0)
    // {
    //     atclient_atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atclient_stringutils_split: %s != public\n", tokens[1]);
    //     ret = 1;
    //     goto exit;
    // }
    // if(strncmp(tokens[2], "publickey", strlen("publickey")) != 0)
    // {
    //     atclient_atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atclient_stringutils_split: %s != publickey\n", tokens[2]);
    //     ret = 1;
    //     goto exit;
    // }

    ret = 0;

    goto exit;
exit:
{
    free(out);
    free(string);
    return ret;
}
}