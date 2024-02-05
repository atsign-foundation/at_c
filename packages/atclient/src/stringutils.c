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
// Find the first non-whitespace character
    const char *start = string;
    while (*start && (*start == ' ' || *start == '\t' || *start == '\n'))
    {
        start++;
    }

    // Find the last non-whitespace character
    const char *end = string + stringlen - 1;
    while (end > start && (*end == ' ' || *end == '\t' || *end == '\n'))
    {
        end--;
    }

    // Calculate the length of the trimmed string
    *outolen = end - start + 1;

    // Check if the output buffer is sufficient
    if (*outolen >= outlen)
    {
        ret = 1;
        goto exit;
    }

    // Copy the trimmed string to the output buffer
    strncpy(out, start, *outolen);
    out[*outolen] = '\0';

    ret = 0;
    goto exit;
exit:
{
    return ret;
}
}

int atclient_stringutils_starts_with(const char *str, const unsigned long sstrlen, const char *prefix)
{
    int ret = -1;
    if (str == NULL || prefix == NULL)
    {
        ret = -1;
        goto exit;
    }

    if (sstrlen == 0)
    {
        ret = -1;
        goto exit;
    }

    ret = strncmp(str, prefix, strlen(prefix));
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

int atclient_stringutils_ends_with(const char *str, const unsigned long sstrlen, const char *suffix)
{
    int ret = -1;
    if(str == NULL || suffix == NULL)
    {
        ret = -1;
        goto exit;
    }
    if(strlen == 0)
    {
        ret = -1;
        goto exit;
    }
    ret = strncmp(str + sstrlen - strlen(suffix), suffix, strlen(suffix));
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

int atclient_stringutils_split(const char *str, const unsigned long sstrlen, const char *delim, char **tokens, const unsigned long tokensarrlen, unsigned long *tokensolen, const unsigned long tokenlen)
{
    int ret = 1;
    if (str == NULL || delim == NULL || tokens == NULL || tokensolen == NULL)
    {
        ret = 1;
        goto exit;
    }

    // Initialize variables
    char *token;
    char *str_copy = strdup(str);  // Duplicate the string to avoid modifying the original
    char *saveptr;

    // Check if strdup failed
    if (str_copy == NULL) {
        ret = -1;  // Indicate memory allocation failure
        goto exit;
    }

    // Tokenize the string
    unsigned long token_count = 0;
    token = strtok_r(str_copy, delim, &saveptr);
    while (token != NULL && token_count < tokensarrlen)
    {
        // Copy the token to the array
        strncpy(tokens[token_count], token, tokenlen - 1);
        tokens[token_count][tokenlen - 1] = '\0';  // Ensure null-terminated

        // Move to the next token
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
