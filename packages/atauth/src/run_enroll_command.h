#ifndef ATAUTH_ENROLL_COMMAND_H
#define ATAUTH_ENROLL_COMMAND_H
#ifdef __cplusplus
extern "C" {
#endif

int atauth_enroll_command(const char *atsign, const char *root_domain, const char *keys_path, const char *passcode,
                          const char *app, const char *device, const char *namespaces, const char *expiry);

#ifdef __cplusplus
}
#endif

#endif
