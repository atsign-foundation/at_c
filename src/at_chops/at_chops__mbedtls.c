#include "at_chops.h"

#ifdef BUILD_MBEDTLS

// Encryption and Decryption - AES
int decryptBytesAES(uint8_t *dst, const size_t dlen, size_t *olen,
                     const uint8_t *src, const size_t slen,
                     const AtEncryptionKey *key,
                     const InitialisationVector *iv);
int decryptStringAES(char *dst, const size_t dlen, size_t *olen,
                      const char *src, const size_t slen,
                      const AtEncryptionKey *key,
                      const InitialisationVector *iv);
int encryptBytesAES(uint8_t *dst, const size_t dlen, size_t *olen,
                     const uint8_t *src, const size_t slen,
                     const AtEncryptionKey *key);
int encryptStringAES(char *dst, const size_t dlen, size_t *olen,
                      const char *src, const size_t slen,
                      const AtEncryptionKey *key);

// Encryption and Decryption - RSA
int decryptBytesRSA(uint8_t *dst, const size_t dlen, size_t *olen,
                     const uint8_t *src, const size_t slen,
                     const AtEncryptionKey *key);
int decryptStringRSA(char *dst, const size_t dlen, size_t *olen,
                      const char *src, const size_t slen,
                      const AtEncryptionKey *key);
int encryptBytesRSA(uint8_t *dst, const size_t dlen, size_t *olen,
                     const uint8_t *src, const size_t slen,
                     const AtEncryptionKey *key);
int encryptStringRSA(char *dst, const size_t dlen, size_t *olen,
                      const char *src, const size_t slen,
                      const AtEncryptionKey *key);

// Hashing
int hashSHA512(uint8_t *dst, const size_t dlen, size_t *olen,
                const uint8_t *src, const size_t slen);

// Signing and Verification - RSA/SHA256
int signBytesRSA_SHA256(uint8_t *dst, const size_t dlen, size_t *olen,
                         const uint8_t *src, const size_t slen,
                         const AtEncryptionKey *key);
int signStringRSA_SHA256(char *dst, const size_t dlen, size_t *olen,
                          const char *src, const size_t slen,
                          const AtEncryptionKey *key);
int verifyBytesRSA_SHA256(const uint8_t *data, const size_t dlen,
                           const uint8_t *sign, const size_t slen,
                           const AtEncryptionKey *key);
int verifyStringRSA_SHA256(const char *data, const size_t dlen,
                            const char *sign, const size_t slen,
                            const AtEncryptionKey *key);

#endif
