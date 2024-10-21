#include "atauth/atactivate_arg_parser.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define DEFAULT_ROOT_SERVER "root.atsign.org"
#define DEFAULT_ROOT_PORT 64

int atactivate_parse_args(int argc, char *argv[], char **atsign, char **cram_secret, char **root_host, int *root_port) {
    int ret = 0;

    int opt;
    
    // Initialize defaults
    *root_host = malloc(strlen(DEFAULT_ROOT_SERVER) + 1);
    if (*root_host == NULL) {
        fprintf(stderr, "Memory allocation failed for root_host\n");
        return -1;
    }
    strcpy(*root_host, DEFAULT_ROOT_SERVER);
    
    *root_port = DEFAULT_ROOT_PORT;

    // Parse command-line arguments
    while ((opt = getopt(argc, argv, "a:c:r:p:")) != -1) {
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
            *root_port = atoi(optarg); // Directly assign the parsed integer
            break;
        default:
            fprintf(stderr, "Usage: %s -a atsign -c cram-secret [-r root-server] [-p port]\n", argv[0]);
            ret = -1;
            goto exit;
        }
    }

    if (*atsign == NULL || *cram_secret == NULL) {
        fprintf(stderr, "Error: -a (atsign) and -c (cram-secret) are mandatory.\n");
        fprintf(stderr, "Usage: %s -a atsign -c cram-secret [-r root-server] [-p port]\n", argv[0]);
        ret = 1;
    }

exit:
    return ret;
}
