#ifndef ATCLIENT_ATSIGN_H
#define ATCLIENT_ATSIGN_H

#include <stddef.h>

// Structure to represent the AtSign class
typedef struct atclient_atsign {
  char *atsign;
  char *without_prefix_str;
} atclient_atsign;

// Function to initialize an AtSign object
int atclient_atsign_init(atclient_atsign *atsign, const char *atsign_str);

// Function to free the memory used by an AtSign object
void atclient_atsign_free(atclient_atsign *atsign);

/**
 * @brief populates *atsign and *atsignlen with the atsign without the prefixed `@` symbol . Calling this function will
 * guarantee that *atsign is always withot a prefixed `@` symbol, whether if it started with one or not.
 *
 * @param atsign the atsign to populate (there will be no prefixed `@` symbol. example: @bob -> bob)
 * @param atsignsize the buffer size
 * @param atsignlen the actually written size of the atsign
 * @param originalatsign the atsign that supposedly has the prefixed `@` symbol you would like to remove
 * @param originalatsignlen the string length of the atsign being read
 * @return int 0 on success, 1 on if atsignsize is not large enough, 2 on if the originalatsignlen length passed is <= 0.
 */
int atclient_atsign_without_at_symbol(char *atsign, const size_t atsignsize, size_t *atsignlen,
                                      const char *originalatsign, const size_t originalatsignlen);

/**
 * @brief populates *atsign and *atsignlen with the atsign with the prefixed `@` symbol. Calling this function will
 *
 * @param atsign the atsign buffer to populate
 * @param atsignsize the buffer size
 * @param atsignlen the actually written size of the atsign
 * @param originalatsign the atsign that supposedly has the prefixed `@` symbol you would like to remove 
 * @param originalatsignlen the string length of the atsign being read
 * @return int 0 on success
 */
int atclient_atsign_with_at_symbol(char *atsign, const size_t atsignsize, size_t *atsignlen,
                                   const char *originalatsign, const size_t originalatsignlen);

#endif
