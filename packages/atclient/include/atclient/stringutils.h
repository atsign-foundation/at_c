#ifndef ATCLIENT_STRINGUTILS_H
#define ATCLIENT_STRINGUTILS_H

int atclient_stringutils_trim_whitespace(const char *string, const unsigned long stringlen, char *out, const unsigned long outlen, unsigned long *outolen);
int atclient_stringutils_starts_with(const char *str, const unsigned long sstrlen, const char *prefix);
int atclient_stringutils_ends_with(const char *str, const unsigned long sstrlen, const char *suffix);
int atclient_stringutils_split(const char *str, const unsigned long sstrlen, const char *delim, char **tokens, const unsigned long tokensarrlen, unsigned long *tokensolen, const unsigned long tokenlen);

#endif