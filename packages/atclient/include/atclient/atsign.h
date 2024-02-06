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
/**
 * @brief populates *atsign and *atsignolen with the atsign without the prefixed `@` symbol . Calling this function will guarantee that *atsign is always withot a prefixed `@` symbol, whether if it started with one or not.
 *
 * @param atsign the atsign to populate (there wil be no prefixd `@` symbol. example: @bob -> bob)
 * @param atsignlen the buffer size
 * @param atsignolen the actually written size
 * @param originalatsign the atsign that supposedly has the prefixed `@` symbol you would liek to remove
 * @param originalatsignlen the string length of the atsign being read
 * @return int 0 on success, 1 on if atsignlen is not large enough, 2 on if the originalatsignlen length passed is <= 0.
 */
int atclient_atsign_without_at_symbol(char *atsign, const unsigned long atsignlen, unsigned long *atsignolen, const char *originalatsign, const unsigned long originalatsignlen);

#endif