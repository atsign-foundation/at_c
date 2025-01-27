#ifndef ATAUTH_ONBOARD_COMMAND_H
#define ATAUTH_ONBOARD_COMMAND_H
#ifdef __cplusplus
extern "C" {
#endif

int atauth_onboard_command(const char *atsign, const char *root_domain, const char *keys_path, const char *cram_key);

#ifdef __cplusplus
}
#endif

#endif
