#ifdef BUILD_MBEDTLS
#ifdef __cplusplus
extern "C"
{
#endif

#include "at_chops.h"
#include "mbedtls/aes.h"
#include "mbedtls/entropy.h"
#include "mbedtls/ctr_drbg.h"
#include "mbedtls/md.h"
#include "mbedtls/pk.h"
#include "mbedtls/rsa.h"
#include "mbedtls/base64.h"

  typedef struct
  {
    unsigned char n;
    unsigned char e;
    unsigned char d;
    unsigned char p;
    unsigned char q;
  } AtRSAKey;

  // Base64 Encode and Decode
  int base64Encode(unsigned char *dst, size_t dlen, size_t *olen,
                   const unsigned char *src, size_t slen)
  {
    return mbedtls_base64_encode(dst, dlen, olen, src, slen);
  }

  int base64Decode(unsigned char *dst, size_t dlen, size_t *olen,
                   const unsigned char *src, size_t slen)
  {
    return mbedtls_base64_decode(dst, dlen, olen, src, slen);
  }

  // Encryption and Decryption - AES
  int initContextAES(AtEncryptionContext *ctx, const AtEncryptionKey *key);
  int decryptBytesAES(unsigned char *dst, const size_t dlen, size_t *olen,
                      const unsigned char *src, const size_t slen,
                      const AtEncryptionKey *key,
                      const InitialisationVector *iv);
  int decryptStringAES(char *dst, const size_t dlen, size_t *olen,
                       const char *src, const size_t slen,
                       const AtEncryptionKey *key,
                       const InitialisationVector *iv);
  int encryptBytesAES(unsigned char *dst, const size_t dlen, size_t *olen,
                      const unsigned char *src, const size_t slen,
                      const AtEncryptionKey *key);
  int encryptStringAES(char *dst, const size_t dlen, size_t *olen,
                       const char *src, const size_t slen,
                       const AtEncryptionKey *key);

  // Encryption and Decryption - RSA
  int initContextRSA(AtEncryptionContext *ctx, const AtEncryptionKey *key)
  {

    mbedtls_rsa_context *rsa = (mbedtls_rsa_context *)ctx;
  }

  int decryptBytesRSA(unsigned char *dst, const size_t dlen, size_t *olen,
                      const unsigned char *src, const size_t slen,
                      const AtEncryptionKey *key)
  {
  }
  int decryptStringRSA(char *dst, const size_t dlen, size_t *olen,
                       const char *src, const size_t slen,
                       const AtEncryptionKey *key)
  {
    return decryptBytesRSA((unsigned char *)dst, dlen, olen, (const unsigned char *)src, slen, key);
  }
  int encryptBytesRSA(unsigned char *dst, const size_t dlen, size_t *olen,
                      const unsigned char *src, const size_t slen,
                      const AtEncryptionKey *key);
  int encryptStringRSA(char *dst, const size_t dlen, size_t *olen,
                       const char *src, const size_t slen,
                       const AtEncryptionKey *key)
  {
    return encryptBytesRSA((unsigned char *)dst, dlen, olen, (const unsigned char *)src, slen, key);
  }

  // Hashing
  int hashSHA512(unsigned char *dst, const size_t dlen, size_t *olen,
                 const unsigned char *src, const size_t slen);

  // Signing and Verification - RSA/SHA256
  int signBytesRSA_SHA256(unsigned char *dst, const size_t dlen, size_t *olen,
                          const unsigned char *src, const size_t slen,
                          const AtEncryptionKey *key);
  int signStringRSA_SHA256(char *dst, const size_t dlen, size_t *olen,
                           const char *src, const size_t slen,
                           const AtEncryptionKey *key);
  int verifyBytesRSA_SHA256(const unsigned char *data, const size_t dlen,
                            const unsigned char *sign, const size_t slen,
                            const AtEncryptionKey *key);
  int verifyStringRSA_SHA256(const char *data, const size_t dlen,
                             const char *sign, const size_t slen,
                             const AtEncryptionKey *key);

#ifdef __cplusplus
}
#endif
#endif
