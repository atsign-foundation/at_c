#include "repl/args.h"
#include <argparse/argparse.h>
#include <atclient/string_utils.h>
#include <atlogger/atlogger.h>
#include <pwd.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>

#define TAG "repl_args"

void repl_args_init(repl_args *repl_args) {
  if (repl_args == NULL) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "Invalid arguments passed to repl_args_init\n");
    return;
  }

  memset(repl_args, 0, sizeof(repl_args));
}

void repl_args_free(repl_args *repl_args) {
  if (repl_args == NULL) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "Invalid arguments passed to repl_args_free\n");
    return;
  }

  if (repl_args->atsign != NULL) {
    // free(repl_args->atsign);
    repl_args->atsign = NULL;
  }

  if (repl_args->root_url != NULL) {
    free(repl_args->root_url);
    repl_args->root_url = NULL;
  }

  if (repl_args->key_file != NULL) {
    free(repl_args->key_file);
    repl_args->key_file = NULL;
  }
}

int repl_args_parse(repl_args *repl_args, const int argc, const char *argv[]) {
  int ret = 1;

  /*
   * 1. Validate arguments
   */
  if (repl_args == NULL || argv == NULL) {
    ret = 1;
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "Invalid arguments passed to repl_args_parse\n");
    return ret;
  }

  /*
   * 2. Parse arguments
   */
  struct argparse_option options[] = {
      OPT_HELP(), OPT_STRING('a', "atsign", &repl_args->atsign, "set the atsign (mandatory)"),
      OPT_STRING(
          'r', "root-url", &repl_args->root_url,
          "url of the atDirectory server that the particular atSign belongs to (defaults to \"root.atsign.org:64\")"),
      OPT_STRING('k', "key-file", &repl_args->key_file,
                 "path to the atKeys file (defaults to \"~/.atsign/keys/@<your_atsign>_key.atKeys\")"),
      OPT_END()};

  struct argparse argparse;
  argparse_init(&argparse, options, NULL, 0);
  argparse_parse(&argparse, argc, (const char **) argv);
  argparse_describe(&argparse, "repl v0.1.0", "");

  /*
   * 3. Ensure mandatory arguments are present
   */
  if (repl_args->atsign == NULL) {
    ret = 1;
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "--atsign is mandatory\n");
    argparse_usage(&argparse);
    goto exit;
  }

  /*
   * 4. Set default values
   */
  if (repl_args->root_url == NULL) {
    repl_args->root_url = strdup(REPL_ARGS_ROOT_URL_DEFAULT);
  }

  if (repl_args->key_file == NULL) {
    char *atsign_without_at = NULL;
    struct passwd *pw = getpwuid(getuid());
    if (pw == NULL) {
      ret = 1;
      atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "Failed to get user's home directory\n");
      goto exit;
    }

    if ((ret = atclient_string_utils_atsign_without_at(repl_args->atsign, &atsign_without_at)) != 0) {
      atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "Failed to get atsign without @ symbol\n");
      goto exit;
    }

    repl_args->key_file = (char *)malloc(strlen(pw->pw_dir) + strlen("/.atsign/keys/@") + strlen(atsign_without_at) +
                              strlen("_key.atKeys") + 1);
    if (repl_args->key_file == NULL) {
      ret = 1;
      atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "Failed to allocate memory for key_file\n");
      free(atsign_without_at);
      goto exit;
    }

    int n =
        snprintf(repl_args->key_file,
                 strlen(pw->pw_dir) + strlen("/.atsign/keys/@") + strlen(atsign_without_at) + strlen("_key.atKeys") + 1,
                 "%s/.atsign/keys/@%s_key.atKeys", pw->pw_dir, atsign_without_at);
    if (n < 0) {
      ret = 1;
      atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "Failed to format key_file path\n");
      free(atsign_without_at);
      goto exit;
    }

    free(atsign_without_at);
  }

  ret = 0;

exit:
  return ret;
}
