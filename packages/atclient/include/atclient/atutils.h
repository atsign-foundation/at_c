#ifndef ATUTILS_H
#define ATUTILS_H

#include "atclient/atsign.h"
#include "atsign.h"
#include "atclient/atkeys.h"

char *trim(char *s);
int starts_with(const char *pre, const char *str);
int ends_with(const char *suffix, const char *str);
char* without_prefix(char* atsign);
char* with_prefix(char* atsign);
char* concatenate_with_prefix(const char* initial_prefix, const char* strings[], int num_strings);

atclient_atkeys load_keys(atsign *atsign);

long long current_time_millis();

#endif