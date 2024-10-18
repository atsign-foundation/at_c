#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>

/* Default values for optional arguments */
#define DEFAULT_ROOT_SERVER "root.atsign.org"
#define DEFAULT_PORT 64

int atactivate_parse_args(int argc, char *argv[], char *atsign, char* cram_secret, char* root_host, char *root_port) {
  int ret = 0;

  int opt;
  char *arg_atsign = NULL;
  char *arg_cram_secret = NULL;
  char *arg_root_host = DEFAULT_ROOT_SERVER;
  int arg_root_port = DEFAULT_PORT;

  /* Option string: a, c, r, p expect arguments */
  while ((opt = getopt(argc, argv, "a:c:r:p:")) != -1) {
    switch (opt) {
    case 'a':
      arg_atsign = optarg;
      break;
    case 'c':
      arg_cram_secret = optarg;
      break;
    case 'r':
      arg_root_host = optarg;
      break;
    case 'p':
      arg_root_port = atoi(optarg); // parse string to int
      break;
    default:
      fprintf(stderr, "Usage: %s -a atsign -c cram-secret [-r root-server] [-p port]\n", argv[0]);
      ret = -1;
      return ret;
    }
  }

  /* Check if mandatory arguments are provided */
  if (arg_atsign == NULL || arg_cram_secret == NULL) {
    fprintf(stderr, "Error: -a (atsign) and -c (cram-secret) are mandatory.\n");
    fprintf(stderr, "Usage: %s -a atsign -c cram-secret [-r root-server] [-p port]\n", argv[0]);
    ret = 1;
    return ret;
  }

  printf("%s\n%s\n%s\n%d\n", arg_atsign, arg_cram_secret, arg_root_host, arg_root_port);

  *atsign = arg_atsign;
  *arg_cram_secret = arg_cram_secret;
  *root_host = arg_root_host;
  *root_port = arg_root_port;

  ret = 0;
  return ret;
}
