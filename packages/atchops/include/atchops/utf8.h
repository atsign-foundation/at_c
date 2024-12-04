#ifndef ATCHOPS_UTF8_H
#define ATCHOPS_UTF8_H
#ifdef __cplusplus
extern "C" {
#endif
#include <atchops/platform.h> // IWYU pragma: keep
#include <stddef.h>

/**
 * @brief UTF_8 encodes a string. Can be used to convert a unsgined char array into bytes
 *
 * @param input pointer to char buffer that is supposed to be encoded
 * @param output double pointer to the output buffer that contains the bytes of the input string
 * @param output_length pointer to the length of the output buffer
 * @return
 */
int atchops_utf8_encode(const char *input, unsigned char **output, size_t *output_length);

#ifdef __cplusplus
}
#endif
#endif
