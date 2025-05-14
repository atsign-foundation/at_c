#include "params.h"
#include "atclient/constants.h"
#include <argparse/argparse.h>
#include <stdio.h>
#include <string.h>

// Note: ret 0 = success, ret 1 = implicit onboard, ret 2 = bad input
static int determine_command(const char *argv1, enum atauth_command *command) {

  switch (argv1[0]) {
  case 'o':
    if (strncmp(argv1, "onboard", strlen("onboard")) == 0) {
      *command = atauth_cmd_onboard;
      return 0;
    }
    return 2;
  case 'e':
    if (strncmp(argv1, "enroll", strlen("enroll")) == 0) {
      *command = atauth_cmd_enroll;
      return 0;
    }
    return 2;
  case '-':
    return 1; // assume implict onboard
  default:
    return 2;
  };
}

static void show_help();
static int parse_onboard_params(struct atauth_params *params, int argc, const char **argv);
static int parse_enroll_params(struct atauth_params *params, int argc, const char **argv);

int parse_atauth_params(struct atauth_params *params, int argc, const char **argv) {

  // Set mandatory values to NULL by default
  params->atsign = NULL;
  params->keys_path = NULL;
  // apply default values to params
  params->root_domain = ATCLIENT_ATDIRECTORY_PRODUCTION_HOST;
  params->verbose = false;

  enum atauth_command command;
  int ret;

  if (argc < 2) { // no arguments passed
    ret = 0;
    command = atauth_cmd_help;
  } else {
    ret = determine_command(argv[1], &command);
  }

  switch (ret) {
  case 0: // use command to determine parsing
    switch (command) {
    case atauth_cmd_onboard:
      return parse_onboard_params(params, argc - 1, argv + 1);
    case atauth_cmd_enroll:
      return parse_enroll_params(params, argc - 1, argv + 1);
    default:
      show_help();
      exit(0);
    }
  case 1: // implicit onboard command
    if (strncmp(argv[1], "-h", strlen("-h")) == 0 || strncmp(argv[1], "--help", strlen("--help")) == 0) {
      show_help();
      exit(0);
    }
    return parse_onboard_params(params, argc, argv);
  default:
    show_help();
    return 1;
  }
}

static void show_help() {
  printf("at_activate <command>\n");
  printf("Commands:\n");
  printf("help:    Show this message\n");
  printf("onboard: Activate a new atSign\n");
  printf("enroll:  Generate a new set of keys for an existing atSign\n");
}

static int parse_onboard_params(struct atauth_params *params, int argc, const char **argv) {
  params->command = atauth_cmd_onboard;
  // set mandatory values to NULL
  params->onboard.cram_key = NULL;

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wmissing-field-initializers"
  struct argparse_option options[] = {
      OPT_HELP(),
      OPT_STRING('a', "atsign", &params->atsign, "Atsign to use (mandatory)"),
      OPT_STRING('k', "keys", &params->keys_path, "Path to the key file"),
      OPT_STRING('r', "rootServer", &params->root_domain, "atDirectory (aka root) server's domain name"),
      OPT_STRING('c', "cramkey", &params->onboard.cram_key, "CRAM key"),
      OPT_BOOLEAN('v', "verbose", &params->verbose, "Enable verbose logging"),
      OPT_END(),
  };
#pragma GCC diagnostic pop

  struct argparse argparse;
  argparse_init(&argparse, options, NULL, 0);
  argparse_describe(&argparse, "onboard command", "");
  argc = argparse_parse(&argparse, argc, argv);

  if (params->atsign == NULL) {
    printf("-a, --atsign is a mandatory argument\n");
    argparse_help_cb(&argparse, options);
    return 1;
  }

  // --keys path is optional for onboard

  if (params->onboard.cram_key == NULL) {
    printf("-c, --cramkey is a mandatory argument\n");
    argparse_help_cb(&argparse, options);
    return 1;
  }

  return 0;
}

static int parse_enroll_params(struct atauth_params *params, int argc, const char **argv) {
  params->command = atauth_cmd_enroll;
  // set mandatory values to NULL
  params->enroll.passcode = NULL;
  params->enroll.app = NULL;
  params->enroll.device = NULL;
  params->enroll.namespaces = NULL;
  // Set optional values to default value
  params->enroll.expiry = NULL;

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wmissing-field-initializers"
  struct argparse_option options[] = {
      OPT_HELP(),
      OPT_STRING('a', "atsign", &params->atsign, "Atsign to use (mandatory)"),
      OPT_STRING('k', "keys", &params->keys_path, "Path to the key file"),
      OPT_STRING('r', "rootServer", &params->root_domain, "atDirectory (aka root) server's domain name"),
      OPT_STRING('s', "passcode", &params->enroll.passcode, "The passcode to present with this enrollment request"),
      OPT_STRING('p', "app", &params->enroll.app, "The name of the app being enrolled"),
      OPT_STRING('d', "device", &params->enroll.device, "A name for the device on which this app is running"),
      OPT_STRING('n', "namespaces", &params->enroll.namespaces,
                 "The namespace access list as comma-separated list of name:value pairs e.g. "
                 "\"buzz:rw,contacts:rw,__manage:rw\""),
      OPT_STRING('e', "expiry", &params->enroll.expiry, ""),
      OPT_BOOLEAN('v', "verbose", &params->verbose, "Enable verbose logging"),
      OPT_END(),
  };
#pragma GCC diagnostic pop

  struct argparse argparse;
  argparse_init(&argparse, options, NULL, 0);
  argparse_describe(&argparse, "enroll command\n", "");
  argc = argparse_parse(&argparse, argc, argv);

  if (params->atsign == NULL) {
    printf("-a, --atsign is a mandatory argument\n");
    argparse_help_cb(&argparse, options);
    return 1;
  }

  if (params->keys_path == NULL) {
    printf("-k, --keys is a mandatory argument\n");
    argparse_help_cb(&argparse, options);
    return 1;
  }

  if (params->enroll.passcode == NULL) {
    printf("-p, --passcode is a mandatory argument\n");
    argparse_help_cb(&argparse, options);
    return 1;
  }

  if (params->enroll.app == NULL) {
    printf("-p, --app is a mandatory argument\n");
    argparse_help_cb(&argparse, options);
    return 1;
  }

  if (params->enroll.device == NULL) {
    printf("-d, --device is a mandatory argument\n");
    argparse_help_cb(&argparse, options);
    return 1;
  }

  if (params->enroll.namespaces == NULL) {
    printf("-n, --namespaces is a mandatory argument\n");
    argparse_help_cb(&argparse, options);
    return 1;
  }

  return 0;
}
