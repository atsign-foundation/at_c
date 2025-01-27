#ifndef ATAUTH_PARAMS_H
#define ATAUTH_PARAMS_H
#ifdef __cplusplus
extern "C" {
#endif

#include <stdbool.h>
#include <stdlib.h>

enum atauth_command {
  atauth_cmd_help,
  atauth_cmd_onboard,
  atauth_cmd_enroll,
};

struct atauth_params {
  char *atsign;
  char *root_domain;
  char *keys_path;
  enum atauth_command command;
  bool verbose;
  union {
    struct {
    } help;
    struct {
      char *cram_key;
    } onboard;
    struct {
      char *passcode;
      char *app;
      char *device;
      char *namespaces;
      char *expiry;
    } enroll;
  };
};

int parse_atauth_params(struct atauth_params *params, int argc, const char **argv);

#ifdef __cplusplus
}
#endif

#endif
