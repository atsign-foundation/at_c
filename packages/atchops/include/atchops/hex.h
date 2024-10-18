#ifndef UTILS_H
#define UTILS_H

#include <stddef.h>

int atchops_hex_to_bytes(const char *hex, unsigned char *bytes, size_t byte_len);

int atchops_bytes_to_hex (char *hex_str, size_t hex_str_len, const unsigned char *bytes, size_t byte_len);

int atchops_utf8_encode(const char *input, unsigned char **output, size_t *output_length);

#endif // UTILS_H
