#include "atauth/atactivate_arg_parser.h"
#include <atclient/constants.h>
#include <atlogger/atlogger.h>
#include <getopt.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <getopt.h>

int parse_root_domain(const char *root_domain_string, char **root_host, int *root_port);

int atactivate_parse_args(const int argc, char *argv[], char **atsign, char **cram_secret, char **otp, char **atkeys_fp,
                          char **app_name, char **device_name, char **namespaces, char **root_host, int *root_port) {
  int ret = 0, opt = 0;
  char *root_fqdn = NULL;
  const char *usage =
      "Usage: \n\tActivate: \t./atactivate -a atsign -c cram-secret [-k atkeys filepath] [-r root-domain]"
      "\n\n\tNew enrollment: ./at_auth_cli -a atsign -s otp/spp -p app_name -d device_name -n "
      "namespaces [-k atkeys filepath+filename to be store keysfile] [-r root-domain]\n\nNotes: \n\t1) namepsaces list"
      " should follow format: \"wavi:rw,buzz:r\"\n\t2) root domain should follow format \"root_domain:port\"\n";

  // Parse command-line arguments
  while ((opt = getopt(argc, argv, "a:c:k:s:p:d:n:r:vh")) != -1) {
    switch (opt) {
    case 'a':
      *atsign = malloc(sizeof(char) * strlen(optarg) + 1);
      if (*atsign == NULL) {
        fprintf(stderr, "Memory allocation failed for atsign\n");
        ret = -1;
        goto exit;
      }
      strcpy(*atsign, optarg);
      break;
    case 'c':
      if (cram_secret == NULL)
        break;
      *cram_secret = malloc(sizeof(char) * strlen(optarg) + 1);
      if (*cram_secret == NULL) {
        fprintf(stderr, "Memory allocation failed for cram_secret\n");
        ret = -1;
        goto exit;
      }
      strcpy(*cram_secret, optarg);
      break;
    case 'k':
      if (atkeys_fp == NULL)
        break;
      *atkeys_fp = malloc(sizeof(char) * strlen(optarg) + 1);
      if (*atkeys_fp == NULL) {
        fprintf(stderr, "Memory allocation failed for atkeys file path\n");
        ret = -1;
        goto exit;
      }
      strcpy(*atkeys_fp, optarg);
      break;
    case 's':
      if (otp == NULL)
        break;
      *otp = malloc(sizeof(char) * strlen(optarg));
      if (*otp == NULL) {
        fprintf(stderr, "Memory allocation failed for OTP\n");
        ret = -1;
        goto exit;
      }
      strcpy(*otp, optarg);
      break;
    case 'p':
      if (app_name == NULL)
        break;
      *app_name = malloc(sizeof(char) * strlen(optarg) + 1);
      if (*app_name == NULL) {
        fprintf(stderr, "Memory reallocation failed for app_name\n");
        ret = -1;
        goto exit;
      }
      strcpy(*app_name, optarg);
      break;
    case 'd':
      if (device_name == NULL)
        break;
      *device_name = malloc(sizeof(char) * strlen(optarg) + 1);
      if (*device_name == NULL) {
        fprintf(stderr, "Memory reallocation failed for device_name\n");
        ret = -1;
        goto exit;
      }
      strcpy(*device_name, optarg);
      break;
    case 'n':
      if (namespaces == NULL)
        break;
      *namespaces = malloc(sizeof(char) * strlen(optarg) + 1);
      if (*namespaces == NULL) {
        fprintf(stderr, "Memory reallocation failed for namespaces\n");
        ret = -1;
        goto exit;
      }
      strcpy(*namespaces, optarg);
      break;
    case 'r':
      root_fqdn = malloc(sizeof(char) * strlen(optarg) + 1);
      if (root_fqdn == NULL) {
        fprintf(stderr, "Memory allocation failed for root_host\n");
        ret = -1;
        goto exit;
      }
      strcpy(root_fqdn, optarg);
      break;
    case 'v':
      atlogger_set_logging_level(ATLOGGER_LOGGING_LEVEL_DEBUG);
      break;
    case 'h':
      fprintf(stdout, "%s", usage);
      ret = 1;
      goto exit;
    default:
      fprintf(stderr, "%s", usage);
      ret = -1;
      goto exit;
    }
  }

  // set default root server address if not provided through CLI
  if (root_fqdn == NULL || parse_root_domain(root_fqdn, root_host, root_port) != 0) {
    *root_host = strdup(ATCLIENT_ATDIRECTORY_PRODUCTION_HOST);
    *root_port = ATCLIENT_ATDIRECTORY_PRODUCTION_PORT;
  }

  if (atsign == NULL) {
    fprintf(stderr, "Error: -a (atsign) is mandatory.\n");
    fprintf(stderr, "%s", usage);
    ret = 1;
  }

  if (cram_secret == NULL && otp == NULL) {
    fprintf(stderr, "Cannot proceed without either of CRAM secret or enroll OTP.\n");
    fprintf(stderr, "%s", usage);
    ret = 1;
  }

exit:
  return ret;
}

int parse_root_domain(const char *root_domain_string, char **root_host, int *root_port) {
  if (root_domain_string == NULL) {
    return 1;
  }
  *root_host = strdup(strtok((char *)root_domain_string, ":"));
  *root_port = atoi(strtok(NULL, ":"));
  if (*root_host == NULL || root_port == NULL) {
    return 1;
  }
  return 0;
}
