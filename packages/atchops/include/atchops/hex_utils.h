#ifndef UTILS_H
#define UTILS_H

#include <stddef.h>

int atchops_hex_to_bytes(const char *hex, unsigned char *bytes, size_t byte_len);

int atchops_bytes_to_hex_string(const unsigned char *input, size_t len, char *output);

int atchops_utf8_encode(const char *input, unsigned char **output, size_t *output_length);

#endif // UTILS_H
