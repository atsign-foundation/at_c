#ifndef ATCLIENT_ATBYTES_H
#define ATCLIENT_ATBYTES_H

#include "atclient/atstr.h"

/**
 * @brief Represents a buffer of bytes. Similar to atclient_atstr
 */
typedef struct atclient_atbytes {
  unsigned long len;    // the allocated length of the buffer
  unsigned char *bytes; // the buffer of bytes (pointer to the first byte in the buffer on the heap)
  unsigned long olen;   // the output length of the buffer
} atclient_atbytes;

/**
 * @brief Initializes atbytes on the heap
 *
 * @param atbytes the atbytes to initialize
 * @param atbyteslen the buffer length to allocate on the heap
 */
void atclient_atbytes_init(atclient_atbytes *atbytes, const unsigned long atbyteslen);

/**
 * @brief Reset atbytes to all zeroes
 *
 * @param atbytes the atbytes to reset
 */
void atclient_atbytes_reset(atclient_atbytes *atbytes);

/**
 * @brief Set atbytes to the given bytes
 *
 * @param atbytes the atbytes to set
 * @param bytes the bytes to set
 * @param byteslen the length of the bytes
 * @return int 0 on success, non-zero on failure
 */
int atclient_atbytes_set(atclient_atbytes *atbytes, const unsigned char *bytes, const unsigned long byteslen);

/**
 * @brief Convert a string to atbytes
 *
 * @param atbytes the atbytes to convert to
 * @param str the string to convert from
 * @param strlen the length of the string
 * @return int 0 on success
 */
int atclient_atbytes_convert(atclient_atbytes *atbytes, const char *str, const unsigned long strlen);

/**
 * @brief Converts an atstr to atbytes
 *
 * @param atbytes atbytes to write to
 * @param atstr the atstr to copy from
 * @return int 0 on success
 */
int atclient_atbytes_convert_atstr(atclient_atbytes *atbytes, const atclient_atstr atstr);

/**
 * @brief Free atbytes on the heap. Should be called once atbytes is no longer needed
 *
 * @param atbytes the atbytes to free
 */
void atclient_atbytes_free(atclient_atbytes *atbytes);

#endif