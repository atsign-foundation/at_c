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

#define STDIN_BUFFER_SIZE 8192

/*
 * Usage:
 * ./repl
 *     -a <atsign>
 *     --root-url [root.atsign.org:64]
 *     --key-file [~/.atsign/keys/@atsign_key.atKeys]
 */

static int set_up_pkam_auth_options(atclient_pkam_authenticate_options *pkam_authenticate_options,
                                    const char *root_url);
static int start_repl_loop(atclient *atclient, repl_args *repl_args);

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

  atclient_pkam_authenticate_options pkam_authenticate_options;
  atclient_pkam_authenticate_options_init(&pkam_authenticate_options);

  atclient atclient;
  atclient_init(&atclient);

  /*
   * 2. Parse arguments
   */
  if (repl_args_parse(&repl_args, argc, (const char **)argv) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "Failed to parse arguments\n");
    goto exit;
  }

  atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_INFO, "atsign: %s\n", repl_args.atsign);
  atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_INFO, "root_url: %s\n", repl_args.root_url);
  atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_INFO, "key_file: %s\n", repl_args.key_file);

  /*
   * 3. PKAM Authenticate
   */
  if ((ret = atclient_atkeys_populate_from_path(&atkeys, repl_args.key_file)) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "Failed to populate atkeys from path\n");
    goto exit;
  }

  if ((ret = set_up_pkam_auth_options(&pkam_authenticate_options, repl_args.root_url)) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "Failed to setup pkam auth options\n");
    goto exit;
  }

  if ((ret = atclient_pkam_authenticate(&atclient, repl_args.atsign, &atkeys, NULL)) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "Failed to authenticate\n");
    goto exit;
  }

  /*
   * 4. REPL Loop
   */
  if ((ret = start_repl_loop(&atclient, &repl_args)) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "Failed to start REPL loop\n");
    goto exit;
  }

  ret = 0;

exit: {
  repl_args_free(&repl_args);
  atclient_atkeys_free(&atkeys);
  atclient_pkam_authenticate_options_free(&pkam_authenticate_options);
  atclient_free(&atclient);
  return ret;
}
}

static int set_up_pkam_auth_options(atclient_pkam_authenticate_options *pkam_authenticate_options,
                                    const char *root_url) {
  int ret = 1;

  if (pkam_authenticate_options == NULL) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "pkam_authenticate_options is NULL\n");
    return ret;
  }

  char *root_url_copy = NULL;

  if (root_url != NULL) {
    root_url_copy = strdup(root_url);
    if (root_url_copy == NULL) {
      atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "Failed to copy root_url\n");
      goto exit;
    }

    char *root_host = strtok(root_url_copy, ":");
    if (root_host == NULL) {
      atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "Failed to get root host\n");
      goto exit;
    }

    char *root_port_str = strtok(NULL, ":");
    if (root_port_str == NULL) {
      atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "Failed to get root port\n");
      goto exit;
    }

    int root_port = atoi(root_port_str);
    if (root_port == 0) {
      atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "Failed to convert root port\n");
      goto exit;
    }

    if ((ret = atclient_pkam_authenticate_options_set_at_directory_host(pkam_authenticate_options, root_host)) != 0) {
      atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "Failed to set at directory host\n");
      goto exit;
    }

    if ((ret = atclient_pkam_authenticate_options_set_at_directory_port(pkam_authenticate_options, root_port)) != 0) {
      atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "Failed to set at directory port\n");
      goto exit;
    }
  }

  ret = 0;

exit: {
  free(root_url_copy);
  return ret;
}
}

static int start_repl_loop(atclient *atclient, repl_args *repl_args) {
  int ret = 1;

  if (atclient == NULL || repl_args == NULL) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "Invalid arguments passed to start_repl_loop\n");
    return ret;
  }

  bool loop = true;

  const size_t stdin_buffer_size = STDIN_BUFFER_SIZE;
  char stdin_buffer[stdin_buffer_size];
  char *stdin_buffer_ptr = stdin_buffer;
  size_t stdin_buffer_len = 0;

  while (loop) {
    memset(stdin_buffer, 0, sizeof(char) * stdin_buffer_size);
    atlogger_log(NULL, ATLOGGER_LOGGING_LEVEL_INFO, "repl> ");
    stdin_buffer_len = getline(&stdin_buffer_ptr, &stdin_buffer_size, stdin);
    if (ret == -1) {
      atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "Failed to read line\n");
      goto exit;
    }
    stdin_buffer_len = stdin_buffer_len - 1; // remove newline

    if (stdin_buffer_len == 0) {
      continue;
    }

    // handle protocol commands
    if (stdin_buffer[0] != '/') {
      unsigned char *cmd = NULL;
      char *recv = NULL;

      const size_t cmd_size = stdin_buffer_len + 2;
      if ((cmd = malloc(sizeof(unsigned char) * cmd_size)) == NULL) {
        atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "Failed to allocate memory for cmd\n");
        goto exit;
      }
      memcpy(cmd, stdin_buffer, stdin_buffer_len);
      cmd[stdin_buffer_len] = '\r';
      cmd[stdin_buffer_len + 1] = '\n';

      ret = atclient_connection_write(&(atclient->atserver_connection), cmd, cmd_size);
      free(cmd);
      if (ret != 0) {
        atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "Failed to send command\n");
        goto exit;
      }

      if((ret = atclient_connection_read(&(atclient->atserver_connection), &recv, NULL, 0)) != 0) {
        atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "Failed to read response\n");
        goto exit;
      }
      atlogger_log(NULL, ATLOGGER_LOGGING_LEVEL_INFO, "recv (%lu): %s\n", strlen(recv), recv);
      free(recv);
      continue;
    }

    // handle slash commands
  }
  atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_INFO, "Exiting REPL loop...\n");
  ret = 0;
exit: { return ret; }
}