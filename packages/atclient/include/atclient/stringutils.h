#ifndef ATCLIENT_STRINGUTILS_H
#define ATCLIENT_STRINGUTILS_H

#include <stddef.h>

/**
 * @brief trims leading/trailing whitespace/newline
 *
 * @param string string to read from
 * @param stringlen the length of the string (use strlen(string) if it is null-terminated)
 * @param out the output buffer
 * @param outsize the size of the output buffer that you allocated
 * @param outlen the output length of the output buffer that is actually used
 * @return int 0 on success, non-zero on failure
 */
int atclient_stringutils_trim_whitespace(const char *string, const size_t stringlen, char *out,
                                         const size_t outsize, size_t *outlen);

/**
 * @brief returns 1 (true) if the string starts with the prefix, 0 (false) otherwise
 *
 * @param string the string to check
 * @param stringlen the length of the string (use strlen(string) if it is null-terminated)
 * @param prefix the prefix to check for
 * @return int 1 (true) if the string starts with the prefix, 0 (false) otherwise
 */
int atclient_stringutils_starts_with(const char *string, const size_t stringlen, const char *prefix,
                                     const size_t prefixlen);

/**
 * @brief returns 1 (true) if the string ends with the suffix, 0 (false) otherwise
 *
 * @param string the string to check
 * @param stringlen the length of the string (use strlen(string) if it is null-terminated)
 * @param suffix the suffix to check for
 * @return int 1 (true) if the string ends with the suffix, 0 (false) otherwise
 */
int atclient_stringutils_ends_with(const char *string, const size_t stringlen, const char *suffix,
                                   const size_t suffixlen);

/**
 * @brief get the length of a long if it were converted to a string
 *
 * @param n the long to check the length of
 * @return int the string length
 */
int long_strlen(long n);

#endif
