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
void atclient_atstr_init(atclient_atstr *atstr, const unsigned long bufferlen);

/**
 * @brief initialize an atstr with a literal string
 *
 * @param atstr the atstr struct to populate
 * @param str the string to set atstr to. best to use string literals here. (or a null-terminated string)
 */
int atclient_atstr_init_literal(atclient_atstr *atstr, const unsigned long bufferlen, const char *format, ...);

/**
 * @brief set an atstr to an empty string
 *
 * @param atstr the atstr struct to reset
 */
void atclient_atstr_reset(atclient_atstr *atstr);

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
int atclient_atstr_set_literal(atclient_atstr *atstr, const char *format, ...);

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

/**
 * @brief Copy what is in original to substring and then set substring to a substring of original
 * 
 * @param substring the atstr to set to the substring. Assumed that this is already initialized (via atclient_atstr_init)
 * @param original the atstr to get the substring from. Assumed that this is already initialized (via atclient_atstr_init)
 * @param start the start index of the substring
 * @param end the end index of the substring
 * @return int 0 on success, non-zero on failure
 */
int atclient_atstr_substring(atclient_atstr *substring, const atclient_atstr original, const unsigned long start, const unsigned long end);

/**
 * @brief Append a string to an atstr
 * 
 * @param atstr the atstr to append to
 * @param format the format of the string to append
 * @param ...   the arguments to format
 * @return int 0 on success
 */
int atclient_atstr_append(atclient_atstr *atstr, const char *format, ...);

/**
 * @brief Returns a set of tokens from a string
 *
 * @param atstr the string to read and split from
 * @param delimiter the delimiter to split the string by
 * @param tokens the array of tokens to populate
 * @param tokensarrlen the size of the tokens array (the max number of tokens to populate)
 * @return int 0 on success, non-zero on failure
 */
int atclient_atstr_split(const atclient_atstr atstr, const char delimiter, char **tokens, const unsigned long tokensarrlen);


#endif