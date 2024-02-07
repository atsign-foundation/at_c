#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <atclient/atlogger.h>
#include <atclient/stringutils.h>

#define TAG "temp"

int main()
{
    int ret = 1;
    printf("starting...\n");

    char *str = malloc(sizeof(char) * 4096);
    memset(str, 0, sizeof(char) * 4096);
    strcpy(str, "cached:public:publickey@bob");
    char **tokens; // array of char pointers
    unsigned long *tokensolen;
    ret = atclient_stringutils_split(str, strlen(str), ":", tokens, tokensolen);
    if(ret != 0)
    {
        atclient_atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atclient_stringutils_split: %d | %s\n", ret, str);
        ret = 1;
        goto exit;
    }

    printf("tokensolen: %lu\n", *tokensolen);
    for(unsigned long i = 0; i < *tokensolen; i++)
    {
        printf("tokens[%lu]: %s\n", i, tokens[i]);
    }
    free(str);
    ret = 0;
exit:
{
    return ret;
}
}