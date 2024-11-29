#ifndef ATCHOPS_HEX_H
#define ATCHOPS_HEX_H
#ifdef __cplusplus
extern "C" {
#endif
#include <stddef.h>

/**
 * @brief Converts a hexadecimal string into a byte array.
 *
 * This function takes a string of hexadecimal characters (e.g., "1a2b3c") and
 * converts it into a byte array (e.g. {0x1a, 0x2b, 0x3c}).
 *
 * @param bytes A pointer to a byte array where the converted values will be stored.
 * @param byte_len The number of bytes to convert. This must be at least half the length of the `hex` string,
 *                 as each byte is represented by two hexadecimal characters.
 * @param hex_str A null-terminated string representing the hexadecimal value to convert.
 *
 * @return 0 on success, or -1 if there was an error (e.g., invalid input, insufficient byte buffer size,
 *         or invalid hexadecimal string).
 */
int atchops_hex_to_bytes(unsigned char *bytes, const size_t byte_len, const char *hex_str);

/**
 * @brief Converts a byte array into a hexadecimal string.
 *
 * This function takes an array of bytes and converts it into a string of hexadecimal
 * characters (e.g., {0x1a, 0x2b, 0x3c} becomes "1a2b3c").
 *
 * @param hex_str A pointer to a character array where the resulting hexadecimal string will be stored.
 *                The array must be large enough to hold the resulting string and a null terminator.
 * @param hex_str_len The size of the `hex_str` buffer in bytes, including space for the null terminator.
 * @param bytes A pointer to the byte array to convert.
 * @param bytes_len The number of bytes in the array to convert.
 *
 * @return 0 on success, or -1 if the `hex_str` buffer is too small to store the resulting string.
 */
int atchops_bytes_to_hex(char *hex_str, const size_t hex_str_len, const unsigned char *bytes, const size_t bytes_len);

#ifdef __cplusplus
}
#endif
#endif
