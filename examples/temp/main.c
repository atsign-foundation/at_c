#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <atlogger/atlogger.h>
#include <atclient/stringutils.h>
#include <atclient/atstr.h>

#define TAG "temp"

int main()
{
    int ret = 1;
    printf("starting...\n");

    char str[32] = "cached:public:publickey@bob";
    char *tokens[32]; // array of char pointers
    unsigned long tokensolen = 0;
    ret = atclient_stringutils_split(str, strlen(str), ":", tokens, &tokensolen);
    if(ret != 0)
    {
        atclient_atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atclient_stringutils_split: %d | %s\n", ret, str);
        ret = 1;
        goto exit;
    }

    printf("tokensolen: %lu\n", tokensolen);
    for(unsigned long i = 0; i < tokensolen; i++)
    {
        printf("tokens[%lu]: %s\n", i, tokens[i]);
    }

    for(unsigned long i = 0; i < 64; i++)
    {
        printf("%c ", str[i]);
    }
    printf("\n");

    ret = 0;
exit:
{
    return ret;
}
}