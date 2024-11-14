#ifndef UTF8_H
#define UTF8_H
#include <stddef.h>

/**
 * 
 * @param input 
 * @param output 
 * @param output_length 
 * @return 
 */
int atchops_utf8_encode(const char *input, unsigned char **output, size_t *output_length);

#endif //UTF8_H
