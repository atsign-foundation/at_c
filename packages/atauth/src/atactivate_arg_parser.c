#include "atauth/atactivate_arg_parser.h"
#include <atlogger/atlogger.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define DEFAULT_ROOT_SERVER "root.atsign.org"
#define DEFAULT_ROOT_PORT 64

/// ToDO: add impl to read the root server FQDN then parse it. Currently only accepts root host, cannot parse root port
int atactivate_parse_args(const int argc, char *argv[], char **atsign, char **cram_secret, char **otp, char **atkeys_fp,
                          char **app_name, char **device_name, char **namespaces, char **root_host) {
  int ret = 0;
  int opt;

  // Initialize defaults
  *root_host = malloc(sizeof(char) * strlen(DEFAULT_ROOT_SERVER) + 1);
  if (*root_host == NULL) {
    fprintf(stderr, "Memory allocation failed for root_host\n");
    return -1;
  }
  strcpy(*root_host, DEFAULT_ROOT_SERVER);

  // Parse command-line arguments
  while ((opt = getopt(argc, argv, "a:c:k:o:p:d:n:r:vh")) != -1) {
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
    case 'o':
      if (otp == NULL)
        break;
      *otp = malloc(sizeof(char) * strlen(optarg));
      if (*otp == NULL) {
        fprintf(stderr, "Memory allocation failed for atkeys file path\n");
        ret = -1;
        goto exit;
      }
      strcpy(*otp, optarg);
      break;
    case 'p':
      if (app_name == NULL)
        break;
      *app_name = realloc(*root_host, sizeof(char) * strlen(optarg) + 1);
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
      *device_name = realloc(*device_name, sizeof(char) * strlen(optarg) + 1);
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
      *namespaces = realloc(*namespaces, sizeof(char) * strlen(optarg) + 1);
      if (*namespaces == NULL) {
        fprintf(stderr, "Memory reallocation failed for namespaces\n");
        ret = -1;
        goto exit;
      }
      strcpy(*namespaces, optarg);
      break;
    case 'r':
      *root_host = realloc(*root_host, sizeof(char) * strlen(optarg) + 1);
      if (*root_host == NULL) {
        fprintf(stderr, "Memory reallocation failed for root_host\n");
        ret = -1;
        goto exit;
      }
      strcpy(*root_host, optarg);
      break;
    case 'v':
      atlogger_set_logging_level(ATLOGGER_LOGGING_LEVEL_DEBUG);
      break;
    case 'h':
      fprintf(stderr, "Usage: %s -a atsign -c cram-secret -o otp [-r root-server] [-p port]\n", argv[0]);
      exit(0); // force exit to display usage
    default:
      fprintf(stderr, "Usage: %s -a atsign -c cram-secret -o otp [-r root-server] [-p port]\n", argv[0]);
      ret = -1;
      goto exit;
    }
  }

  if (atsign == NULL) {
    fprintf(stderr, "Error: -a (atsign) is mandatory.\n");
    fprintf(stderr, "Usage: %s -a atsign -c cram-secret -o otp [-r root-server] [-p port]\n", argv[0]);
    ret = 1;
  }

  if (cram_secret == NULL && otp == NULL) {
    fprintf(stderr, "Cannot proceed without either of CRAM secret or enroll OTP.\n");
    fprintf(stderr, "Usage: %s -a atsign -c cram-secret -o otp [-r root-server] [-p port]\n", argv[0]);
    ret = 1;
  }

exit:
  return ret;
}
