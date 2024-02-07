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
 * @brief splits a string into tokens. each token is written to the tokens array and is null-terminated.
 *
 * @param string the string to split, this will not be modified
 * @param stringlen the length of the string (use strlen(string) if it is null-terminated)
 * @param delim the delimiter to split the string by
 * @param tokens the array of strings to write to
 * @param tokensarrlen the length of the tokens array (maximum number of tokens)
 * @param tokensolen the numbers of tokens actually used in the array
 * @param tokenlen the string max length of each individual token
 * @return int 0 on success, non-zero on failure
 */
int atclient_stringutils_split(char *string, const unsigned long stringlen, const char *delim, char **tokens, unsigned long *tokensolen)
;


#endif