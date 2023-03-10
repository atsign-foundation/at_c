#pragma once

#ifdef __cplusplus
extern "C"
{
#endif

#include <stddef.h>

// Header Definitions
// Bit 0 : 0 = symmetric, 1 = asymmetric
// Bit 1 : 0 = private, 1 = public
// Bit 2-4 : Encryption Algorithm (AES, RSA, ECC, etc.)
// Bit 5-7: Encryption Key Length (128, 192, 256, etc.)

// Bit 0
#define AT_KEYSTORE_DEF_SYMMETRIC 0b0
#define AT_KEYSTORE_DEF_ASYMMETRIC 0b1

// Bit 1
#define AT_KEYSTORE_DEF_PRIVATE 0b00
#define AT_KEYSTORE_DEF_PUBLIC 0b10

// Bits 2-4
#define AT_KEYSTORE_DEF_AES 0b000 00

#define AT_KEYSTORE_DEF_RSA 0b000 00
#define AT_KEYSTORE_DEF_ECC 0b001 00

// Bits 5-7
#define AT_KEYSTORE_KEYLEN_AES_128 0b000 000 00
#define AT_KEYSTORE_KEYLEN_AES_192 0b001 000 00
#define AT_KEYSTORE_KEYLEN_AES_256 0b010 000 00

#define AT_KEYSTORE_KEYLEN_RSA_2048 0b000 000 00
#define AT_KEYSTORE_KEYLEN_RSA_4096 0b001 000 00

#define AT_KEYSTORE_KEYLEN_ECC_112 0b000 000 00
#define AT_KEYSTORE_KEYLEN_ECC_224 0b001 000 00

// Bits 0-1
#define AT_KEYSTORE_TYPE_ASYMMETRIC_PRIVATE (unsigned char)(AT_KEYSTORE_TYPE_ASYMMETRIC | AT_KEYSTORE_TYPE_PRIVATE)
#define AT_KEYSTORE_TYPE_ASYMMETRIC_PUBLIC (unsigned char)(AT_KEYSTORE_TYPE_ASYMMETRIC | AT_KEYSTORE_TYPE_PUBLIC)

// Bits 0-4
#define AT_KEYSTORE_TYPE_AES (unsigned char)(AT_KEYSTORE_ALGORITHM_AES | AT_KEYSTORE_TYPE_SYMMETRIC)

#define AT_KEYSTORE_TYPE_RSA_PRIVATE (unsigned char)(AT_KEYSTORE_ALGORITHM_RSA | AT_KEYSTORE_TYPE_ASYMMETRIC_PRIVATE)
#define AT_KEYSTORE_TYPE_RSA_PUBLIC (unsigned char)(AT_KEYSTORE_ALGORITHM_RSA | AT_KEYSTORE_TYPE_ASYMMETRIC_PUBLIC)

#define AT_KEYSTORE_TYPE_ECC_PRIVATE (unsigned char)(AT_KEYSTORE_ALGORITHM_ECC | AT_KEYSTORE_TYPE_ASYMMETRIC_PRIVATE)
#define AT_KEYSTORE_TYPE_ECC_PUBLIC (unsigned char)(AT_KEYSTORE_ALGORITHM_ECC | AT_KEYSTORE_TYPE_ASYMMETRIC_PUBLIC)

// Bits 0-7
#define AT_KEYSTORE_TYPE_AES_128 (unsigned char)(AT_KEYSTORE_TYPE_AES | AT_KEYSTORE_KEYLEN_AES_128)
#define AT_KEYSTORE_TYPE_AES_192 (unsigned char)(AT_KEYSTORE_TYPE_AES | AT_KEYSTORE_KEYLEN_AES_192)
#define AT_KEYSTORE_TYPE_AES_256 (unsigned char)(AT_KEYSTORE_TYPE_AES | AT_KEYSTORE_KEYLEN_AES_256)

#define AT_KEYSTORE_TYPE_RSA_2048_PRIVATE (unsigned char)(AT_KEYSTORE_TYPE_RSA_PRIVATE | AT_KEYSTORE_KEYLEN_RSA_2048)
#define AT_KEYSTORE_TYPE_RSA_2048_PUBLIC (unsigned char)(AT_KEYSTORE_TYPE_RSA_PUBLIC | AT_KEYSTORE_KEYLEN_RSA_2048)
#define AT_KEYSTORE_TYPE_RSA_4096_PRIVATE (unsigned char)(AT_KEYSTORE_TYPE_RSA_PRIVATE | AT_KEYSTORE_KEYLEN_RSA_4096)
#define AT_KEYSTORE_TYPE_RSA_4096_PUBLIC (unsigned char)(AT_KEYSTORE_TYPE_RSA_PUBLIC | AT_KEYSTORE_KEYLEN_RSA_4096)

#define AT_KEYSTORE_TYPE_ECC_112_PRIVATE (unsigned char)(AT_KEYSTORE_TYPE_ECC_PRIVATE | AT_KEYSTORE_KEYLEN_ECC_112)
#define AT_KEYSTORE_TYPE_ECC_112_PUBLIC (unsigned char)(AT_KEYSTORE_TYPE_ECC_PUBLIC | AT_KEYSTORE_KEYLEN_ECC_112)
#define AT_KEYSTORE_TYPE_ECC_224_PRIVATE (unsigned char)(AT_KEYSTORE_TYPE_ECC_PRIVATE | AT_KEYSTORE_KEYLEN_ECC_224)
#define AT_KEYSTORE_TYPE_ECC_224_PUBLIC (unsigned char)(AT_KEYSTORE_TYPE_ECC_PUBLIC | AT_KEYSTORE_KEYLEN_ECC_224)

  typedef struct
  {
    unsigned char header;
    void *key;
  } AtEncryptionKey;

  typedef struct
  {
    unsigned char header;
    void *ctx;
  } AtEncryptionContext;

  typedef struct
  {
    size_t vecLen;
    unsigned char vec[];
  } InitialisationVector; // TODO determine if this is still needed now that context has been added

  // Base64 Encode and Decode

  /**
   * \brief          Encode a buffer into base64 format
   *
   * \param dst      destination buffer
   * \param dlen     size of the destination buffer
   * \param olen     number of bytes written
   * \param src      source buffer
   * \param slen     amount of data to be encoded
   *
   * \return         0 if successful, or MBEDTLS_ERR_BASE64_BUFFER_TOO_SMALL.
   *                 *olen is always updated to reflect the amount
   *                 of data that has (or would have) been written.
   *                 If that length cannot be represented, then no data is
   *                 written to the buffer and *olen is set to the maximum
   *                 length representable as a size_t.
   *
   * \note           Call this function with dlen = 0 to obtain the
   *                 required buffer size in *olen
   */
  extern int base64Encode(unsigned char *dst, size_t dlen, size_t *olen,
                          const unsigned char *src, size_t slen);

  /**
   * \brief          Decode a base64-formatted buffer
   *
   * \param dst      destination buffer (can be NULL for checking size)
   * \param dlen     size of the destination buffer
   * \param olen     number of bytes written
   * \param src      source buffer
   * \param slen     amount of data to be decoded
   *
   * \return         0 if successful, MBEDTLS_ERR_BASE64_BUFFER_TOO_SMALL, or
   *                 MBEDTLS_ERR_BASE64_INVALID_CHARACTER if the input data is
   *                 not correct. *olen is always updated to reflect the amount
   *                 of data that has (or would have) been written.
   *
   * \note           Call this function with *dst = NULL or dlen = 0 to obtain
   *                 the required buffer size in *olen
   */
  extern int base64Decode(unsigned char *dst, size_t dlen, size_t *olen,
                          const unsigned char *src, size_t slen);

  // Encryption and Decryption - AES

  /**
   * \brief          Initialize an AES context from an AES key
   *
   * \param ctx      destination context (can be NULL for checking size)
   * \param key      encryption key
   *
   * \return         0 if successful, or an error code
   */
  extern int initContextAES(AtEncryptionContext *ctx, const AtEncryptionKey *key);

  /**
   * \brief          Decrypts a buffer using AES
   *
   * \param dst      destination buffer (can be NULL for checking size)
   * \param dlen     size of the destination buffer
   * \param olen     number of bytes written
   * \param src      source buffer
   * \param slen     amount of data in the source buffer
   * \param key      encryption key
   * \param iv       initialisation vector
   *
   * \return         0 if successful, or an error code
   *
   * \note           Call this function with *dst = NULL or dlen = 0 to obtain
   *                 the required buffer size in *olen
   */
  extern int
  decryptBytesAES(unsigned char *dst, const size_t dlen, size_t *olen,
                  const unsigned char *src, const size_t slen,
                  const AtEncryptionKey *key,
                  const InitialisationVector *iv);
  /**
   * \brief          Decrypts a buffer using AES
   *
   * \param dst      destination buffer (can be NULL for checking size)
   * \param dlen     size of the destination buffer
   * \param olen     number of bytes written
   * \param src      source buffer
   * \param slen     amount of data in the source buffer
   * \param key      encryption key
   * \param iv       initialisation vector
   *
   * \return         0 if successful, or an error code
   *
   * \note           Call this function with *dst = NULL or dlen = 0 to obtain
   *                 the required buffer size in *olen
   */
  extern int decryptStringAES(char *dst, const size_t dlen, size_t *olen,
                              const char *src, const size_t slen,
                              const AtEncryptionKey *key,
                              const InitialisationVector *iv);
  /**
   * \brief          Encrypts a buffer using AES
   *
   * \param dst      destination buffer (can be NULL for checking size)
   * \param dlen     size of the destination buffer
   * \param olen     number of bytes written
   * \param src      source buffer
   * \param slen     amount of data in the source buffer
   * \param key      encryption key
   *
   * \return         0 if successful, or an error code
   *
   * \note           Call this function with *dst = NULL or dlen = 0 to obtain
   *                 the required buffer size in *olen
   */
  extern int encryptBytesAES(unsigned char *dst, const size_t dlen, size_t *olen,
                             const unsigned char *src, const size_t slen,
                             const AtEncryptionKey *key);
  /**
   * \brief          Encrypts a buffer using AES
   *
   * \param dst      destination buffer (can be NULL for checking size)
   * \param dlen     size of the destination buffer
   * \param olen     number of bytes written
   * \param src      source buffer
   * \param slen     amount of data in the source buffer
   * \param key      encryption key
   *
   * \return         0 if successful, or an error code
   *
   * \note           Call this function with *dst = NULL or dlen = 0 to obtain
   *                 the required buffer size in *olen
   */
  extern int encryptStringAES(char *dst, const size_t dlen, size_t *olen,
                              const char *src, const size_t slen,
                              const AtEncryptionKey *key);

  // TODO - add ECC encryption and decryption
  // // Encryption and Decryption - ECC

  // /**
  //  * \brief          Decrypts a buffer using ECC
  //  *
  //  * \param dst      destination buffer (can be NULL for checking size)
  //  * \param dlen     size of the destination buffer
  //  * \param olen     number of bytes written
  //  * \param src      source buffer
  //  * \param slen     amount of data in the source buffer
  //  * \param key      encryption key
  //  * \param iv       initialisation vector
  //  *
  //  * \return         0 if successful, or an error code
  //  *
  //  * \note           Call this function with *dst = NULL or dlen = 0 to obtain
  //  *                 the required buffer size in *olen
  //  */
  // extern int decryptBytesECC(unsigned char *dst, const const size_t dlen, size_t *olen,
  //                             const unsigned char *src, const size_t slen,
  //                             const AtEncryptionKey *key,
  //                             const InitialisationVector *iv);
  // /**
  //  * \brief          Decrypts a buffer using ECC
  //  *
  //  * \param dst      destination buffer (can be NULL for checking size)
  //  * \param dlen     size of the destination buffer
  //  * \param olen     number of bytes written
  //  * \param src      source buffer
  //  * \param slen     amount of data in the source buffer
  //  * \param key      encryption key
  //  * \param iv       initialisation vector
  //  *
  //  * \return         0 if successful, or an error code
  //  *
  //  * \note           Call this function with *dst = NULL or dlen = 0 to obtain
  //  *                 the required buffer size in *olen
  //  */
  // extern int decryptStringECC(char *dst, const size_t dlen, size_t *olen,
  //                              const char *src, const size_t slen,
  //                              const AtEncryptionKey *key,
  //                              const InitialisationVector *iv);
  // /**
  //  * \brief          Encrypts a buffer using ECC
  //  *
  //  * \param dst      destination buffer (can be NULL for checking size)
  //  * \param dlen     size of the destination buffer
  //  * \param olen     number of bytes written
  //  * \param src      source buffer
  //  * \param slen     amount of data in the source buffer
  //  * \param key      encryption key
  //  *
  //  * \return         0 if successful, or an error code
  //  *
  //  * \note           Call this function with *dst = NULL or dlen = 0 to obtain
  //  *                 the required buffer size in *olen
  //  */
  // extern int encryptBytesECC(unsigned char *dst, const size_t dlen, size_t *olen,
  //                             const unsigned char *src, const size_t slen,
  //                             const AtEncryptionKey *key);
  // /**
  //  * \brief          Encrypts a buffer using ECC
  //  *
  //  * \param dst      destination buffer (can be NULL for checking size)
  //  * \param dlen     size of the destination buffer
  //  * \param olen     number of bytes written
  //  * \param src      source buffer
  //  * \param slen     amount of data in the source buffer
  //  * \param key      encryption key
  //  *
  //  * \return         0 if successful, or an error code
  //  *
  //  * \note           Call this function with *dst = NULL or dlen = 0 to obtain
  //  *                 the required buffer size in *olen
  //  */
  // extern int encryptStringECC(char *dst, const size_t dlen, size_t *olen,
  //                              const char *src, const size_t slen,
  //                              const AtEncryptionKey *key);

  // // Encryption and Decryption - RSA

  /**
   * \brief          Initialize an RSA context from an RSA key
   *
   * \param ctx      destination context (can be NULL for checking size)
   * \param key      encryption key
   *
   * \return         0 if successful, or an error code
   */
  extern int initContextRSA(AtEncryptionContext *ctx, const AtEncryptionKey *key);

  /**
   * \brief          Decrypts a buffer using RSA
   *
   * \param dst      destination buffer (can be NULL for checking size)
   * \param dlen     size of the destination buffer
   * \param olen     number of bytes written
   * \param src      source buffer
   * \param slen     amount of data in the source buffer
   * \param key      encryption key
   *
   * \return         0 if successful, or an error code
   *
   * \note           Call this function with *dst = NULL or dlen = 0 to obtain
   *                 the required buffer size in *olen
   */
  extern int decryptBytesRSA(unsigned char *dst, const size_t dlen, size_t *olen,
                             const unsigned char *src, const size_t slen,
                             const AtEncryptionKey *key);
  /**
   * \brief          Decrypts a buffer using RSA
   *
   * \param dst      destination buffer (can be NULL for checking size)
   * \param dlen     size of the destination buffer
   * \param olen     number of bytes written
   * \param src      source buffer
   * \param slen     amount of data in the source buffer
   * \param key      encryption key
   *
   * \return         0 if successful, or an error code
   *
   * \note           Call this function with *dst = NULL or dlen = 0 to obtain
   *                 the required buffer size in *olen
   */
  extern int decryptStringRSA(char *dst, const size_t dlen, size_t *olen,
                              const char *src, const size_t slen,
                              const AtEncryptionKey *key);
  /**
   * \brief          Encrypts a buffer using RSA
   *
   * \param dst      destination buffer (can be NULL for checking size)
   * \param dlen     size of the destination buffer
   * \param olen     number of bytes written
   * \param src      source buffer
   * \param slen     amount of data in the source buffer
   * \param key      encryption key
   *
   * \return         0 if successful, or an error code
   *
   * \note           Call this function with *dst = NULL or dlen = 0 to obtain
   *                 the required buffer size in *olen
   */
  extern int encryptBytesRSA(unsigned char *dst, const size_t dlen, size_t *olen,
                             const unsigned char *src, const size_t slen,
                             const AtEncryptionKey *key);
  /**
   * \brief          Encrypts a buffer using RSA
   *
   * \param dst      destination buffer (can be NULL for checking size)
   * \param dlen     size of the destination buffer
   * \param olen     number of bytes written
   * \param src      source buffer
   * \param slen     amount of data in the source buffer
   * \param key      encryption key
   *
   * \return         0 if successful, or an error code
   *
   * \note           Call this function with *dst = NULL or dlen = 0 to obtain
   *                 the required buffer size in *olen
   */
  extern int encryptStringRSA(char *dst, const size_t dlen, size_t *olen,
                              const char *src, const size_t slen,
                              const AtEncryptionKey *key);

  // Hashing

  /**
   * \brief          Computes the SHA512 hash of a buffer
   *
   * \param dst      destination buffer (can be NULL for checking size)
   * \param dlen     size of the destination buffer
   * \param olen     number of bytes written
   * \param src      source buffer
   * \param slen     amount of data in the source buffer
   *
   * \return         0 if successful, or an error code
   *
   * \note           Call this function with *dst = NULL or dlen = 0 to obtain
   *                 the required buffer size in *olen
   */
  extern int hashSHA512(unsigned char *dst, const size_t dlen, size_t *olen,
                        const unsigned char *src, const size_t slen);

  // Signing and Verification - RSA/SHA256

  /**
   * \brief          Signs a buffer using RSA and SHA256
   *
   * \param dst      destination buffer (can be NULL for checking size)
   * \param dlen     size of the destination buffer
   * \param olen     number of bytes written
   * \param src      source buffer
   * \param slen     amount of data in the source buffer
   * \param key      encryption key
   *
   * \return         0 if successful, or an error code
   *
   * \note           Call this function with *dst = NULL or dlen = 0 to obtain
   *                 the required buffer size in *olen
   */
  extern int signBytesRSA_SHA256(unsigned char *dst, const size_t dlen, size_t *olen,
                                 const unsigned char *src, const size_t slen,
                                 const AtEncryptionKey *key);
  /**
   * \brief          Signs a buffer using RSA and SHA256
   *
   * \param dst      destination buffer (can be NULL for checking size)
   * \param dlen     size of the destination buffer
   * \param olen     number of bytes written
   * \param src      source buffer
   * \param slen     amount of data in the source buffer
   * \param key      encryption key
   *
   * \return         0 if successful, or an error code
   *
   * \note           Call this function with *dst = NULL or dlen = 0 to obtain
   *                 the required buffer size in *olen
   */
  extern int signStringRSA_SHA256(char *dst, const size_t dlen, size_t *olen,
                                  const char *src, const size_t slen,
                                  const AtEncryptionKey *key);
  /**
   * \brief          Verifies data against a signature using RSA and SHA256
   *
   * \param data     data (can be NULL for checking size)
   * \param dlen     size of the data
   * \param sign     signature
   * \param slen     size of the signature
   * \param key      encryption key
   *
   * \return         0 if successful, or an error code
   */
  extern int verifyBytesRSA_SHA256(const unsigned char *data, const size_t dlen,
                                   const unsigned char *sign, const size_t slen,
                                   const AtEncryptionKey *key);
  /**
   * \brief          Verifies data against a signature using RSA and SHA256
   *
   * \param data     data (can be NULL for checking size)
   * \param dlen     size of the data
   * \param sign     signature
   * \param slen     size of the signature
   * \param key      encryption key
   *
   * \return         0 if successful, or an error code
   */
  extern int verifyStringRSA_SHA256(const char *data, const size_t dlen,
                                    const char *sign, const size_t slen,
                                    const AtEncryptionKey *key);
#ifdef __cplusplus
}
#endif
