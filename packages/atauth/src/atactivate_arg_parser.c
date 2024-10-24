#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>

#define DEFAULT_ROOT_SERVER "root.atsign.org"
#define DEFAULT_ROOT_PORT 64

int atactivate_parse_args(int argc, char *argv[], char **atsign, char **cram_secret, char **root_host, int **root_port) {
  int ret = 0;

  int opt;
  *root_host = DEFAULT_ROOT_SERVER;
  *root_port = DEFAULT_ROOT_PORT;

  /* Option string: a, c, r, p expect arguments */
  while ((opt = getopt(argc, argv, "a:c:r:p:")) != -1) {
    switch (opt) {
    case 'a':
      *atsign = optarg;
      break;
    case 'c':
      *cram_secret = optarg;
      break;
    case 'r':
      *root_host = optarg;
      break;
    case 'p':
      *root_port = atoi(optarg); // parse string to int
      break;
    default:
      fprintf(stderr, "Usage: %s -a atsign -c cram-secret [-r root-server] [-p port]\n", argv[0]);
      ret = -1;
      return ret;
    }
  }

  if (*atsign == NULL || *cram_secret == NULL) {
    fprintf(stderr, "Error: -a (atsign) and -c (cram-secret) are mandatory.\n");
    fprintf(stderr, "Usage: %s -a atsign -c cram-secret [-r root-server] [-p port]\n", argv[0]);
    ret = 1;
    return ret;
  }

  ret = 0;
  return ret;
}
