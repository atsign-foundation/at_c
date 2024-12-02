#include "atauth/atactivate_arg_parser.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define DEFAULT_ROOT_SERVER "root.atsign.org"
#define DEFAULT_ROOT_PORT 64

int atactivate_parse_args(int argc, char *argv[], char **atsign, char **cram_secret, char **otp, char **atkeys_fp,
                          char **root_host, int *root_port) {
  int ret = 0;
  int opt;

  // Initialize defaults
  *root_host = malloc(sizeof(char) * strlen(DEFAULT_ROOT_SERVER) + 1);
  if (*root_host == NULL) {
    fprintf(stderr, "Memory allocation failed for root_host\n");
    return -1;
  }
  strcpy(*root_host, DEFAULT_ROOT_SERVER);
  root_port = malloc(sizeof(int));
  if (root_port == NULL) {
    fprintf(stderr, "Memory allocation failed for root_port\n");
    return -1;
  }
  *root_port = DEFAULT_ROOT_PORT;

  // Parse command-line arguments
  while ((opt = getopt(argc, argv, "a:c:k:o:r:p:h")) != -1) {
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
      *cram_secret = malloc(sizeof(char) * strlen(optarg) + 1);
      if (*cram_secret == NULL) {
        fprintf(stderr, "Memory allocation failed for cram_secret\n");
        ret = -1;
        goto exit;
      }
      strcpy(*cram_secret, optarg);
      break;
    case 'k':
      *atkeys_fp = malloc(sizeof(char) * strlen(optarg) + 1);
      if (*atkeys_fp == NULL) {
        fprintf(stderr, "Memory allocation failed for atkeys file path\n");
        ret = -1;
        goto exit;
      }
      strcpy(*atkeys_fp, optarg);
      break;
    case 'o':
      *otp = malloc(sizeof(char) * strlen(optarg));
      if(*otp == NULL) {
        fprintf(stderr, "Memory allocation failed for atkeys file path\n");
        ret = -1;
        goto exit;
      }
      strcpy(*otp, optarg);
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
    case 'p':
      *root_port = atoi(optarg);
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

  if (*atsign == NULL) {
    fprintf(stderr, "Error: -a (atsign) is mandatory.\n");
    fprintf(stderr, "Usage: %s -a atsign -c cram-secret -o otp [-r root-server] [-p port]\n", argv[0]);
    ret = 1;
  }

  if(*cram_secret == NULL && *otp == NULL) {
    fprintf(stderr, "Cannot proceed without either of CRAM secret on enroll OTP.\n");
    fprintf(stderr, "Usage: %s -a atsign -c cram-secret -o otp [-r root-server] [-p port]\n", argv[0]);
    ret = 1;
  }

exit:
  return ret;
}
