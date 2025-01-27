#include "atlogger/atlogger.h"
#include "params.h"
#include "run_enroll_command.h"
#include "run_onboard_command.h"
#include <atauth/at_activate.h>
#include <string.h>

#if defined(ATAUTH_BUILD_EXECUTABLES)
int main(int argc, const char **argv) { return at_activate(argc, argv); }
#endif

int at_activate(int argc, const char **argv) {
  int ret = 0;
  struct atauth_params params;
  ret = parse_atauth_params(&params, argc, argv);
  if (ret != 0) {
    return ret;
  }

  if (params.verbose) {
    atlogger_set_logging_level(ATLOGGER_LOGGING_LEVEL_DEBUG);
  } else {
    atlogger_set_logging_level(ATLOGGER_LOGGING_LEVEL_INFO);
  }

  // ensure atSign starts with '@'
  size_t atsign_len = strlen(params.atsign);
  size_t off = 0;
  char *atsign;
  if (params.atsign[0] != '@') {
    atsign_len++;
    off = 1;
  }
  atsign = malloc(sizeof(char) * (atsign_len + 1));
  if (atsign == NULL) {
    atlogger_log("at_activate", ATLOGGER_LOGGING_LEVEL_ERROR, "Failed to allocate memory for atsign\n");
    return 1;
  }
  atsign[0] = '@';
  memcpy(atsign + off, params.atsign, atsign_len);
  atsign[atsign_len] = 0;

  // run the appropriate command
  switch (params.command) {
  case atauth_cmd_help:
    ret = 0; // noop, help text will already be displayed
    break;
  case atauth_cmd_onboard:
    ret = atauth_onboard_command(atsign, params.root_domain, params.keys_path, params.onboard.cram_key);
    break;
  case atauth_cmd_enroll:
    ret = atauth_enroll_command(atsign, params.root_domain, params.keys_path, params.enroll.passcode, params.enroll.app,
                                params.enroll.device, params.enroll.namespaces, params.enroll.expiry);
    break;
  }

  free(atsign);
  return ret;
}
