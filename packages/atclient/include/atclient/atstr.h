#ifndef ATCLIENT_ATSTR_H
#define ATCLIENT_ATSTR_H

/**
 * @brief Represents a string that is allocated on the heap
 */
typedef struct atclient_atstr
{
    unsigned long len;  // buffer length
    char *str;          // string
    unsigned long olen; // output length (length of string)
} atclient_atstr;

/**
 * @brief Initialize an atstr
 *
 * @param atstr pointer to atstr to initialize
 * @param bufferlen length of buffer to allocate in bytes (recommended to use a number that is a power of 2)
 */
void atclient_atstr_init(atclient_atstr *atstr, unsigned long bufferlen);

/**
 * @brief Free an atstr
 *
 * @param atstr pointer to atstr to free from the heap
 */
void atclient_atstr_free(atclient_atstr *atstr);

#endif