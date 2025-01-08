#ifndef FUNCTIONAL_TESTS_HELPERS_H
#define FUNCTIONAL_TESTS_HELPERS_H
#ifdef __cplusplus
extern "C" {
#endif

#include "atclient/atclient.h"
#include <stddef.h>

int functional_tests_set_up_atkeys(atclient_atkeys *atkeys, const char *atsign);
int functional_tests_pkam_auth(atclient *atclient, atclient_atkeys *atkeys, const char *atsign);
int functional_tests_publickey_exists(atclient *atclient, const char *key, const char *shared_by,
                                      const char *knamespace);
int functional_tests_selfkey_exists(atclient *atclient, const char *key, const char *shared_by, const char *knamespace);
int functional_tests_sharedkey_exists(atclient *atclient, const char *key, const char *shared_by,
                                      const char *shared_with, const char *knamespace);
int functional_tests_tear_down_sharedenckeys(atclient *atclient, const char *recipient);


/**
 * @brief Get the atkeys absolute file path for the given atSign. It will look inside of `~/.atsign/keys/` directory.
 *
 * @param atsign the atSign string, must begin with @ (Example: "@bob"). Assumed to be null terminated string
 * @param path a null pointer that will be allocated which will hold the absolute path. Example result would be "/home/jeremy/.atsign/keys/@alice_key.atKeys". It will return a null terminated string. The variable will be malloc'd and must be freed by the caller.
 * @return int, 0 on success
 */
int functional_tests_get_atkeys_path(const char *atsign, char **path);

#ifdef __cplusplus
}
#endif
#endif
