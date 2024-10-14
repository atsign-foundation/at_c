#include "repl/args.h"
#include <atclient/atclient.h>
#include <atclient/atclient_utils.h>
#include <atclient/atkeys.h>
#include <atclient/atkeys_file.h>
#include <atclient/connection.h>
#include <atlogger/atlogger.h>
#include <pwd.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define TAG "repl"

/*
 * Usage:
 * ./repl
 *     -a <atsign>
 *     --root-url [root.atsign.org:64]
 *     --key-file [~/.atsign/keys/@atsign_key.atKeys]
 */

int main(int argc, char *argv[]) {
  int ret = 1;

  atlogger_set_logging_level(ATLOGGER_LOGGING_LEVEL_DEBUG);

  /*
   * 1. Variables
   */
  repl_args repl_args;
  repl_args_init(&repl_args);

  atclient_atkeys atkeys;
  atclient_atkeys_init(&atkeys);

  atclient atclient;
  atclient_init(&atclient);

  /*
   * 2. Parse arguments
   */
  if (repl_args_parse(&repl_args, argc, (const char **) argv) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "Failed to parse arguments\n");
    goto exit;
  }

  atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_INFO, "atsign: %s\n", repl_args.atsign);
  atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_INFO, "root_url: %s\n", repl_args.root_url);
  atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_INFO, "key_file: %s\n", repl_args.key_file);

  /*
   * 3. PKAM Authenticate
   */
  if((ret = atclient_atkeys_populate_from_path(&atkeys, repl_args.key_file)) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "Failed to populate atkeys from path\n");
    goto exit;
  }

  if((ret = atclient_pkam_authenticate(&atclient, repl_args.atsign, &atkeys, NULL)) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "Failed to authenticate\n");
    goto exit;
  }

  ret = 0;

exit: {
  repl_args_free(&repl_args);
  atclient_atkeys_free(&atkeys);
  atclient_free(&atclient);
  return ret;
}
}
