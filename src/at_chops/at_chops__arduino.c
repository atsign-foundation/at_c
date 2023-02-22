#include "at_chops.h"

#ifdef BUILD_ARDUINO
// TODO @JeremyTubongbanua
// Encryption and Decryption - AES
void decryptBytesAES(uint8_t *dst, const size_t dlen, size_t *olen,
                     const uint8_t *src, const size_t slen,
                     const AtEncryptionKey *key,
                     const InitialisationVector *iv);
void decryptStringAES(char *dst, const size_t dlen, size_t *olen,
                      const char *src, const size_t slen,
                      const AtEncryptionKey *key,
                      const InitialisationVector *iv);
void encryptBytesAES(uint8_t *dst, const size_t dlen, size_t *olen,
                     const uint8_t *src, const size_t slen,
                     const AtEncryptionKey *key);
void encryptStringAES(char *dst, const size_t dlen, size_t *olen,
                      const char *src, const size_t slen,
                      const AtEncryptionKey *key);

// Encryption and Decryption - ECC
void decryptBytesECC(uint8_t *dst, const const size_t dlen, size_t *olen,
                     const uint8_t *src, const size_t slen,
                     const AtEncryptionKey *key,
                     const InitialisationVector *iv);
void decryptStringECC(char *dst, const size_t dlen, size_t *olen,
                      const char *src, const size_t slen,
                      const AtEncryptionKey *key,
                      const InitialisationVector *iv);
void encryptBytesECC(uint8_t *dst, const size_t dlen, size_t *olen,
                     const uint8_t *src, const size_t slen,
                     const AtEncryptionKey *key);
void encryptStringECC(char *dst, const size_t dlen, size_t *olen,
                      const char *src, const size_t slen,
                      const AtEncryptionKey *key);

// Encryption and Decryption - RSA
void decryptBytesRSA(uint8_t *dst, const size_t dlen, size_t *olen,
                     const uint8_t *src, const size_t slen,
                     const AtEncryptionKey *key);
void decryptStringRSA(char *dst, const size_t dlen, size_t *olen,
                      const char *src, const size_t slen,
                      const AtEncryptionKey *key);
void encryptBytesRSA(uint8_t *dst, const size_t dlen, size_t *olen,
                     const uint8_t *src, const size_t slen,
                     const AtEncryptionKey *key);
void encryptStringRSA(char *dst, const size_t dlen, size_t *olen,
                      const char *src, const size_t slen,
                      const AtEncryptionKey *key);

// Hashing
void hashSHA512(uint8_t *dst, const size_t dlen, size_t *olen,
                const uint8_t *src, const size_t slen);

// Signing and Verification - RSA/SHA256
void signBytesRSA_SHA256(uint8_t *dst, const size_t dlen, size_t *olen,
                         const uint8_t *src, const size_t slen,
                         const AtEncryptionKey *key);
void signStringRSA_SHA256(char *dst, const size_t dlen, size_t *olen,
                          const char *src, const size_t slen,
                          const AtEncryptionKey *key);
bool verifyBytesRSA_SHA256(const uint8_t *data, const size_t dlen,
                           const uint8_t *sign, const size_t slen,
                           const AtEncryptionKey *key);
bool verifyStringRSA_SHA256(const char *data, const size_t dlen,
                            const char *sign, const size_t slen,
                            const AtEncryptionKey *key);

#endif
