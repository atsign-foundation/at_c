#ifndef ATCHOPS_MBEDTLS_H
#define ATCHOPS_MBEDTLS_H
#ifdef __cplusplus
extern "C" {
#endif

#include <atchops/platform.h>    // IWYU pragma: keep
#include <mbedtls/aes.h>         // IWYU pragma: export
#include <mbedtls/asn1.h>        // IWYU pragma: export
#include <mbedtls/base64.h>      // IWYU pragma: export
#include <mbedtls/ctr_drbg.h>    // IWYU pragma: export
#include <mbedtls/entropy.h>     // IWYU pragma: export
#include <mbedtls/error.h>       // IWYU pragma: export
#include <mbedtls/md.h>          // IWYU pragma: export
#include <mbedtls/md5.h>         // IWYU pragma: export
#include <mbedtls/net_sockets.h> // IWYU pragma: export
#include <mbedtls/rsa.h>         // IWYU pragma: export
#include <mbedtls/ssl.h>         // IWYU pragma: export
#include <mbedtls/x509_crt.h>    // IWYU pragma: export

extern const mbedtls_md_type_t atchops_mbedtls_md_map[];

#ifdef __cplusplus
}
#endif
#endif
