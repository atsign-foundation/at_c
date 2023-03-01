#pragma once

#ifdef __cplusplus
extern "C"
{
#endif

#include <stddef.h>  // size_t
#include <stdint.h>  // uint8_t
#include <stdint.h> // int

#include "at_keystore.h"

  typedef struct
  {
    size_t vecLen;
    uint8_t vec[];
  } InitialisationVector;

  // Encryption and Decryption - AES

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
  decryptBytesAES(uint8_t *dst, const size_t dlen, size_t *olen,
                  const uint8_t *src, const size_t slen,
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
  extern int encryptBytesAES(uint8_t *dst, const size_t dlen, size_t *olen,
                              const uint8_t *src, const size_t slen,
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
  // extern int decryptBytesECC(uint8_t *dst, const const size_t dlen, size_t *olen,
  //                             const uint8_t *src, const size_t slen,
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
  // extern int encryptBytesECC(uint8_t *dst, const size_t dlen, size_t *olen,
  //                             const uint8_t *src, const size_t slen,
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

  // /**
  //  * \brief          Decrypts a buffer using RSA
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
  extern int decryptBytesRSA(uint8_t *dst, const size_t dlen, size_t *olen,
                              const uint8_t *src, const size_t slen,
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
  extern int encryptBytesRSA(uint8_t *dst, const size_t dlen, size_t *olen,
                              const uint8_t *src, const size_t slen,
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
  extern int hashSHA512(uint8_t *dst, const size_t dlen, size_t *olen,
                         const uint8_t *src, const size_t slen);

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
  extern int signBytesRSA_SHA256(uint8_t *dst, const size_t dlen, size_t *olen,
                                  const uint8_t *src, const size_t slen,
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
  extern int verifyBytesRSA_SHA256(const uint8_t *data, const size_t dlen,
                                    const uint8_t *sign, const size_t slen,
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
