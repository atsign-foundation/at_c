#ifndef FUNCTIONAL_TESTS_HELPERS_H
#define FUNCTIONAL_TESTS_HELPERS_H

#include "atclient/atclient.h"
#include <stddef.h>

int functional_tests_set_up_atkeys(atclient_atkeys *atkeys, const char *atsign, const size_t atsignlen);
int functional_tests_pkam_auth(atclient *atclient, atclient_atkeys *atkeys, const char *atsign, const size_t atsignlen);
int functional_tests_publickey_exists(atclient *atclient, const char *key, const char *sharedby,
                                      const char *knamespace);
int functional_tests_selfkey_exists(atclient *atclient, const char *key, const char *sharedby, const char *knamespace);
int functional_tests_sharedkey_exists(atclient *atclient, const char *key, const char *sharedby, const char *sharedwith,
                                      const char *knamespace);
int functional_tests_tear_down_sharedenckeys(atclient *atclient, const char *recipient);                                      

#endif
