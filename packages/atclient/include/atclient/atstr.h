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
 * @param bufferlen length of buffer to allocate in bytes (recommended to use a number that is a power of 2). the bufferlen is the length of the buffer generated. we do not add 1 for null terminator.
 */
void atclient_atstr_init(atclient_atstr *atstr, unsigned long bufferlen);

/**
 * @brief initialize an atstr with a literal string
 *
 * @param atstr the atstr struct to populate
 * @param str the string to set atstr to. best to use string literals here. (or a null-terminated string)
 */
void atclient_atstr_init_literal(atclient_atstr *atstr, const char *str);

/**
 * @brief set an atstr to a string
 *
 * @param atstr the atstr struct to populate
 * @param str the string to set atstr to
 * @param len the length of the string
 */
int atclient_atstr_set(atclient_atstr *atstr, const char *str, const unsigned long len);

/**
 * @brief Set an atstr to a literal string, assumed to be null-terminated
 *
 * @param atstr atstr struct to populate
 * @param str null-terminated string to set atstr to. Best to use string literals here
 */
int atclient_atstr_set_literal(atclient_atstr *atstr, const char *str);

/**
 * @brief Copy what is in an atstr to another atstr
 *
 * @param atstr pointer that is being overwritten
 * @param data pointer that is being copied from
 */
int atclient_atstr_copy(atclient_atstr *atstr, atclient_atstr *data);

/**
 * @brief Free an atstr
 *
 * @param atstr pointer to atstr to free from the heap
 */
void atclient_atstr_free(atclient_atstr *atstr);

#endif