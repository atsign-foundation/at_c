#include <string.h>
#include <stdlib.h>
#include <ctype.h>
#include "atclient/stringutils.h"

int atclient_stringutils_trim_whitespace(const char *string, const unsigned long stringlen, char *out, const unsigned long outlen, unsigned long *outolen)
{
    int ret = 1;

    if (string == NULL)
    {
        ret = 1;
        goto exit;
    }

    if (stringlen == 0)
    {
        ret = 1;
        goto exit;
    }

    // remove whitespace newlinetrailing/leading
    const char *start = string;
    while (*start && (*start == ' ' || *start == '\t' || *start == '\n'))
    {
        start++;
    }

    const char *end = string + stringlen - 1;
    while (end > start && (*end == ' ' || *end == '\t' || *end == '\n'))
    {
        end--;
    }

    *outolen = end - start + 1;

    if (*outolen >= outlen)
    {
        ret = 1;
        goto exit;
    }

    strncpy(out, start, *outolen);
    out[*outolen] = '\0';

    ret = 0;
    goto exit;
exit:
{
    return ret;
}
}

int atclient_stringutils_starts_with(const char *string, const unsigned long stringlen, const char *prefix)
{
    int ret = -1;
    if (string == NULL || prefix == NULL)
    {
        ret = -1;
        goto exit;
    }

    if (stringlen == 0)
    {
        ret = -1;
        goto exit;
    }

    ret = strncmp(string, prefix, strlen(prefix));
    if(ret == 0)
    {
        ret = 1; // true
    }
    else if(ret != 0)
    {
        ret = 0; // false
    }

    goto exit;
exit:
{
    return ret;
}
}

int atclient_stringutils_ends_with(const char *string, const unsigned long stringlen, const char *suffix)
{
    int ret = -1;
    if(string == NULL || suffix == NULL)
    {
        ret = -1;
        goto exit;
    }
    if(strlen == 0)
    {
        ret = -1;
        goto exit;
    }
    ret = strncmp(string + stringlen - strlen(suffix), suffix, strlen(suffix));
    if(ret == 0)
    {
        ret = 1; // true
    }
    else if(ret != 0)
    {
        ret = 0; // false
    }

    goto exit;
exit:
{
    return ret;
}
}

int atclient_stringutils_split(const char *string, const unsigned long stringlen, const char *delim, char **tokens, const unsigned long tokensarrlen, unsigned long *tokensolen, const unsigned long tokenlen)
{
    int ret = 1;
    if (string == NULL || delim == NULL || tokens == NULL || tokensolen == NULL)
    {
        ret = 1;
        goto exit;
    }

    char *token;
    char *str_copy = strdup(string);  // Duplicate the string to avoid modifying the original
    char *saveptr;

    if (str_copy == NULL) {
        ret = -1;  // Indicate memory allocation failure
        goto exit;
    }

    unsigned long token_count = 0;
    token = strtok_r(str_copy, delim, &saveptr);
    while (token != NULL && token_count < tokensarrlen)
    {
        strncpy(tokens[token_count], token, tokenlen - 1);
        tokens[token_count][tokenlen - 1] = '\0';  // Ensure null-terminated

        token = strtok_r(NULL, delim, &saveptr);
        token_count++;
    }

    // Store the number of tokens generated in the variable pointed to by tokenolen
    *tokensolen = token_count;

    ret = 0;

exit:
    // Free the duplicated string
    if (str_copy != NULL) {
        free(str_copy);
    }
    return ret;
}
