#ifndef ATCLIENT_STRINGUTILS_H
#define ATCLIENT_STRINGUTILS_H

/**
 * @brief trims leading/trailing whitespace/newline
 *
 * @param string string to read from
 * @param stringlen the length of the string (use strlen(string) if it is null-terminated)
 * @param out the output buffer
 * @param outlen the size of the output buffer that you allocated
 * @param outolen the output length of the output buffer that is actually used
 * @return int 0 on success, non-zero on failure
 */
int atclient_stringutils_trim_whitespace(const char *string, const unsigned long stringlen, char *out, const unsigned long outlen, unsigned long *outolen);

/**
 * @brief returns 1 (true) if the string starts with the prefix, 0 (false) otherwise
 *
 * @param string the string to check
 * @param stringlen the length of the string (use strlen(string) if it is null-terminated)
 * @param prefix the prefix to check for
 * @return int 1 (true) if the string starts with the prefix, 0 (false) otherwise
 */
int atclient_stringutils_starts_with(const char *string, const unsigned long stringlen, const char *prefix, const unsigned long prefixlen);

/**
 * @brief returns 1 (true) if the string ends with the suffix, 0 (false) otherwise
 *
 * @param string the string to check
 * @param stringlen the length of the string (use strlen(string) if it is null-terminated)
 * @param suffix the suffix to check for
 * @return int 1 (true) if the string ends with the suffix, 0 (false) otherwise
 */
int atclient_stringutils_ends_with(const char *string, const unsigned long stringlen, const char *suffix, const unsigned long suffixlen);

/**
 * @brief splits a string into tokens based on a delimier. Replaces that delimiter with a null terminator.
 * (e.g. "cached:public:publickey@bob" would yield 4 tokens: "cached", "public", "publickey", "bob")
 * the string would be modified to be "cached\0public\0publickey\0bob\0"
 * It is assumed that the string passed in is writable, can be modified, has enough space to be modified and is not const.
 * You cannot use a string literal. You must pass in a char buffer either via malloc or something like `char str[64] = "...";`
 * It is assumed tokens is an array of pointers to char arrays that are writable and can be modified. Assumed that there are enough 
 * pointers in the array to hold all the tokens.
 *
 * @param string the string to split. This will be modified. (e.g. char str[64] = "cached:public:publickey@bob";)
 * @param stringlen the length of the string (use strlen(string) if it is null-terminated)
 * @param delim the delimiter to split on
 * @param tokens an array of pointers to the tokens in the string (e.g. char *tokens[4])
 * @param tokensolen the amount of tokens evaluated
 * @return int 0 on success
 */
int atclient_stringutils_split(char *string, const unsigned long stringlen, const char *delim, char **tokens, unsigned long *tokensolen);


#endif