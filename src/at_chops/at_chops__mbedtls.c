#include "at_chops.h"

#ifdef BUILD_MBEDTLS

// Encryption and Decryption - AES
void decryptBytes_AES(uint8_t *dst, const size_t dlen, size_t *olen,
                      const uint8_t *src, const size_t slen,
                      const AtEncryptionKey *key,
                      const InitialisationVector *iv);
void decryptString_AES(char *dst, const size_t dlen, size_t *olen,
                       const char *src, const size_t slen,
                       const AtEncryptionKey *key,
                       const InitialisationVector *iv);
void encryptBytes_AES(uint8_t *dst, const size_t dlen, size_t *olen,
                      const uint8_t *src, const size_t slen,
                      const AtEncryptionKey *key);
void encryptString_AES(char *dst, const size_t dlen, size_t *olen,
                       const char *src, const size_t slen,
                       const AtEncryptionKey *key);

// Encryption and Decryption - ECC
void decryptBytes_ECC(uint8_t *dst, const const size_t dlen, size_t *olen,
                      const uint8_t *src, const size_t slen,
                      const AtEncryptionKey *key,
                      const InitialisationVector *iv);
void decryptString_ECC(char *dst, const size_t dlen, size_t *olen,
                       const char *src, const size_t slen,
                       const AtEncryptionKey *key,
                       const InitialisationVector *iv);
void encryptBytes_ECC(uint8_t *dst, const size_t dlen, size_t *olen,
                      const uint8_t *src, const size_t slen,
                      const AtEncryptionKey *key);
void encryptString_ECC(char *dst, const size_t dlen, size_t *olen,
                       const char *src, const size_t slen,
                       const AtEncryptionKey *key);

// Encryption and Decryption - RSA
void decryptBytes_RSA(uint8_t *dst, const size_t dlen, size_t *olen,
                      const uint8_t *src, const size_t slen,
                      const AtEncryptionKey *key);
void decryptString_RSA(char *dst, const size_t dlen, size_t *olen,
                       const char *src, const size_t slen,
                       const AtEncryptionKey *key);
void encryptBytes_RSA(uint8_t *dst, const size_t dlen, size_t *olen,
                      const uint8_t *src, const size_t slen,
                      const AtEncryptionKey *key);
void encryptString_RSA(char *dst, const size_t dlen, size_t *olen,
                       const char *src, const size_t slen,
                       const AtEncryptionKey *key);

// Hashing
void hash_SHA512(uint8_t *dst, const size_t dlen, size_t *olen,
                 const uint8_t *src, const size_t slen);

// Signing and Verification - RSA/SHA256
void signBytes_RSA_SHA256(uint8_t *dst, const size_t dlen, size_t *olen,
                          const uint8_t *src, const size_t slen,
                          const AtEncryptionKey *key);
void signString_RSA_SHA256(char *dst, const size_t dlen, size_t *olen,
                           const char *src, const size_t slen,
                           const AtEncryptionKey *key);
bool verifyBytes_RSA_SHA256(const uint8_t *data, const size_t dlen,
                            const uint8_t *sign, const size_t slen,
                            const AtEncryptionKey *key);
bool verifyString_RSA_SHA256(const char *data, const size_t dlen,
                             const char *sign, const size_t slen,
                             const AtEncryptionKey *key);

#endif
