#ifndef ATCLIENT_ATSIGN_H
#define ATCLIENT_ATSIGN_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>

// Structure to represent the AtSign class
typedef struct atsign {
    char* atsign;
    char* without_prefix_str;
} atsign;

// Function to initialize an AtSign object
void atsign_init(atsign* atsign, const char* atsign_str);

// Function to free the memory used by an AtSign object
void free_atsign(atsign* atsign);

#endif