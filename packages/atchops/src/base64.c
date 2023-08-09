#include <stddef.h>
#include <mbedtls/base64.h>

int atchops_base64_encode(unsigned char *dst, size_t dstlen, size_t *writtenlen, const unsigned char *src, const size_t srclen)
{
    return mbedtls_base64_encode(
        dst,
        dstlen,
        writtenlen,
        src,
        srclen);
}

int atchops_base64_decode(unsigned char *dst, size_t dstlen, size_t *writtenlen, const unsigned char *src, const size_t srclen)
{
    return mbedtls_base64_decode(
        dst,
        dstlen,
        writtenlen,
        src,
        srclen);
}
