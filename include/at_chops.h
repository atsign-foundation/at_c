#pragma once

#ifdef __cplusplus
extern "C"
{
#endif
  typedef struct
  {
    unsigned long size;
    void *key;
  } AtEncryptionKey;

  typedef struct
  {
    unsigned char header;
    unsigned long size;
    void *ctx;
  } AtEncryptionContext;

  typedef struct
  {
    unsigned long len;
    unsigned char *iv;
  } InitialisationVector;

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
   *                 length representable as a unsigned long.
   *
   * \note           Call this function with dlen = 0 to obtain the
   *                 required buffer size in *olen
   */
  extern int base64_encode(unsigned char *dst, unsigned long dlen, unsigned long *olen,
                           const unsigned char *src, unsigned long slen);

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
  extern int base64_decode(unsigned char *dst, unsigned long dlen, unsigned long *olen,
                           const unsigned char *src, unsigned long slen);

  // // Encryption and Decryption - AES

  /**
   * \brief          Initializes an AES context suitable for CTR encrypt/decrypt
   *
   * \param ctx      AES context to be initialized
   * \param key      base64 encoded AES key
   *
   * \return         0 if successful, or an error code
   */
  extern int init_context_aes(AtEncryptionContext *ctx,
                              const AtEncryptionKey *key);

  /**
   * \brief          Decrypts a buffer using AES
   *
   * \param dst      destination buffer (can be NULL for checking size)
   * \param dlen     size of the destination buffer
   * \param olen     number of bytes written
   * \param src      source buffer
   * \param slen     amount of data in the source buffer
   * \param key      AES encryption key
   * \param iv       initialisation vector
   *
   * \return         0 if successful, or an error code
   *
   * \note           Call this function with *dst = NULL or dlen = 0 to obtain
   *                 the required buffer size in *olen
   */
  extern int decrypt_bytes_aes_ctr(unsigned char *dst,
                                   unsigned long dlen,
                                   unsigned long *olen,
                                   const unsigned char *src,
                                   const unsigned long slen,
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
   * \param key      AES encryption key
   * \param iv       initialisation vector
   *
   * \return         0 if successful, or an error code
   *
   * \note           Call this function with *dst = NULL or dlen = 0 to obtain
   *                 the required buffer size in *olen
   */
  extern int decrypt_string_aes_ctr(char *dst,
                                    unsigned long dlen,
                                    unsigned long *olen,
                                    const char *src,
                                    const unsigned long slen,
                                    const AtEncryptionKey *key,
                                    const InitialisationVector *iv);
  /**
   * \brief          Encrypts a buffer using AES
   *
   * \param dst      destination buffer
   * \param dlen     size of the destination buffer
   * \param olen     number of bytes written
   * \param src      source buffer
   * \param slen     amount of data in the source buffer
   * \param key      AES encryption key
   * \param iv       initialisation vector
   *
   * \return         0 if successful, or an error code
   *
   * \note           The key must be base64 decoded before calling this function
   *
   */
  extern int encrypt_bytes_aes_ctr(unsigned char *dst,
                                   unsigned long dlen,
                                   unsigned long *olen,
                                   const unsigned char *src,
                                   const unsigned long slen,
                                   const AtEncryptionKey *key,
                                   InitialisationVector *iv);
  /**
   * \brief          Encrypts a buffer using AES
   *
   * \param dst      destination buffer
   * \param dlen     size of the destination buffer
   * \param olen     number of bytes written
   * \param src      source buffer
   * \param slen     amount of data in the source buffer
   * \param key      AES encryption key
   * \param iv       initialisation vector
   *
   * \return         0 if successful, or an error code
   *
   * \note           The key must be base64 decoded before calling this function
   *
   */
  extern int encrypt_string_aes_ctr(char *dst,
                                    unsigned long dlen,
                                    unsigned long *olen,
                                    const char *src,
                                    const unsigned long len,
                                    const AtEncryptionKey *key,
                                    InitialisationVector *iv);

  // // TODO - add ECC encryption and decryption
  // // // Encryption and Decryption - ECC

  // // /**
  // //  * \brief          Decrypts a buffer using ECC
  // //  *
  // //  * \param dst      destination buffer (can be NULL for checking size)
  // //  * \param dlen     size of the destination buffer
  // //  * \param olen     number of bytes written
  // //  * \param src      source buffer
  // //  * \param slen     amount of data in the source buffer
  // //  * \param key      encryption key
  // //  * \param iv       initialisation vector
  // //  *
  // //  * \return         0 if successful, or an error code
  // //  *
  // //  * \note           Call this function with *dst = NULL or dlen = 0 to obtain
  // //  *                 the required buffer size in *olen
  // //  */
  // // extern int decryptBytesECC(unsigned char *dst, const const unsigned long dlen, unsigned long *olen,
  // //                             const unsigned char *src, const unsigned long slen,
  // //                             const AtEncryptionKey *key,
  // //                             const InitialisationVector *iv);
  // // /**
  // //  * \brief          Decrypts a buffer using ECC
  // //  *
  // //  * \param dst      destination buffer (can be NULL for checking size)
  // //  * \param dlen     size of the destination buffer
  // //  * \param olen     number of bytes written
  // //  * \param src      source buffer
  // //  * \param slen     amount of data in the source buffer
  // //  * \param key      encryption key
  // //  * \param iv       initialisation vector
  // //  *
  // //  * \return         0 if successful, or an error code
  // //  *
  // //  * \note           Call this function with *dst = NULL or dlen = 0 to obtain
  // //  *                 the required buffer size in *olen
  // //  */
  // // extern int decryptStringECC(char *dst, const unsigned long dlen, unsigned long *olen,
  // //                              const char *src, const unsigned long slen,
  // //                              const AtEncryptionKey *key,
  // //                              const InitialisationVector *iv);
  // // /**
  // //  * \brief          Encrypts a buffer using ECC
  // //  *
  // //  * \param dst      destination buffer (can be NULL for checking size)
  // //  * \param dlen     size of the destination buffer
  // //  * \param olen     number of bytes written
  // //  * \param src      source buffer
  // //  * \param slen     amount of data in the source buffer
  // //  * \param key      encryption key
  // //  *
  // //  * \return         0 if successful, or an error code
  // //  *
  // //  * \note           Call this function with *dst = NULL or dlen = 0 to obtain
  // //  *                 the required buffer size in *olen
  // //  */
  // // extern int encryptBytesECC(unsigned char *dst, const unsigned long dlen, unsigned long *olen,
  // //                             const unsigned char *src, const unsigned long slen,
  // //                             const AtEncryptionKey *key);
  // // /**
  // //  * \brief          Encrypts a buffer using ECC
  // //  *
  // //  * \param dst      destination buffer (can be NULL for checking size)
  // //  * \param dlen     size of the destination buffer
  // //  * \param olen     number of bytes written
  // //  * \param src      source buffer
  // //  * \param slen     amount of data in the source buffer
  // //  * \param key      encryption key
  // //  *
  // //  * \return         0 if successful, or an error code
  // //  *
  // //  * \note           Call this function with *dst = NULL or dlen = 0 to obtain
  // //  *                 the required buffer size in *olen
  // //  */
  // // extern int encryptStringECC(char *dst, const unsigned long dlen, unsigned long *olen,
  // //                              const char *src, const unsigned long slen,
  // //                              const AtEncryptionKey *key);

  // // // Encryption and Decryption - RSA

  // /**
  //  * \brief          Initialize an RSA context from an RSA key
  //  *
  //  * \param ctx      destination context (can be NULL for checking size)
  //  * \param key      encryption key
  //  * \param pwd      password to decrypt the key
  //  * \param pwdlen   length of the password
  //  * \param f_rng    RNG function
  //  * \param p_rng    RNG parameter
  //  *
  //  * \return         0 if successful, or an error code
  //  *
  //  * \note          f_rng and p_rng can be left NULL, in which case the
  //  *               mbedtls library's default entropy source is used.
  //  */
  // extern int initContextRSA(AtEncryptionContext *ctx, const AtEncryptionKey *key,
  //                           const unsigned char *pwd, unsigned long pwdlen,
  //                           int (*f_rng)(void *, unsigned char *, unsigned long), void *p_rng);

  // /**
  //  * \brief          Initialize an RSA context from an RSA key
  //  *
  //  * \param ctx      destination context (can be NULL for checking size)
  //  * \param filename filename of the key
  //  * \param pwd      password to decrypt the key
  //  * \param pwdlen   length of the password
  //  * \param f_rng    RNG function
  //  * \param p_rng    RNG parameter
  //  *
  //  * \return         0 if successful, or an error code
  //  *
  //  * \note          f_rng and p_rng can be left NULL, in which case the
  //  *               mbedtls library's default entropy source is used.
  //  */
  // extern int initContextFromFileRSA(AtEncryptionContext *ctx, const char *path,
  //                                   const unsigned char *pwd, unsigned char key_type,
  //                                   int (*f_rng)(void *, unsigned char *, unsigned long), void *p_rng);

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
  // extern int decryptBytesRSA(unsigned char *dst, const unsigned long dlen, unsigned long *olen,
  //                            const unsigned char *src, const unsigned long slen,
  //                            const AtEncryptionKey *key);
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
  // extern int decryptStringRSA(char *dst, const unsigned long dlen, unsigned long *olen,
  //                             const char *src, const unsigned long slen,
  //                             const AtEncryptionKey *key);
  // /**
  //  * \brief          Encrypts a buffer using RSA
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
  // extern int encryptBytesRSA(unsigned char *dst, const unsigned long dlen, unsigned long *olen,
  //                            const unsigned char *src, const unsigned long slen,
  //                            const AtEncryptionKey *key);
  // /**
  //  * \brief          Encrypts a buffer using RSA
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
  // extern int encryptStringRSA(char *dst, const unsigned long dlen, unsigned long *olen,
  //                             const char *src, const unsigned long slen,
  //                             const AtEncryptionKey *key);

  // // Hashing

  // /**
  //  * \brief          Computes the SHA512 hash of a buffer
  //  *
  //  * \param dst      destination buffer (can be NULL for checking size)
  //  * \param dlen     size of the destination buffer
  //  * \param olen     number of bytes written
  //  * \param src      source buffer
  //  * \param slen     amount of data in the source buffer
  //  *
  //  * \return         0 if successful, or an error code
  //  *
  //  * \note           Call this function with *dst = NULL or dlen = 0 to obtain
  //  *                 the required buffer size in *olen
  //  */
  // extern int hashSHA512(unsigned char *dst, const unsigned long dlen, unsigned long *olen,
  //                       const unsigned char *src, const unsigned long slen);

  // // Signing and Verification - RSA/SHA256

  // /**
  //  * \brief          Signs a buffer using RSA and SHA256
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
  // extern int signBytesRSA_SHA256(unsigned char *dst, const unsigned long dlen, unsigned long *olen,
  //                                const unsigned char *src, const unsigned long slen,
  //                                const AtEncryptionKey *key);
  // /**
  //  * \brief          Signs a buffer using RSA and SHA256
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
  // extern int signStringRSA_SHA256(char *dst, const unsigned long dlen, unsigned long *olen,
  //                                 const char *src, const unsigned long slen,
  //                                 const AtEncryptionKey *key);
  // /**
  //  * \brief          Verifies data against a signature using RSA and SHA256
  //  *
  //  * \param data     data (can be NULL for checking size)
  //  * \param dlen     size of the data
  //  * \param sign     signature
  //  * \param slen     size of the signature
  //  * \param key      encryption key
  //  *
  //  * \return         0 if successful, or an error code
  //  */
  // extern int verifyBytesRSA_SHA256(const unsigned char *data, const unsigned long dlen,
  //                                  const unsigned char *sign, const unsigned long slen,
  //                                  const AtEncryptionKey *key);
  // /**
  //  * \brief          Verifies data against a signature using RSA and SHA256
  //  *
  //  * \param data     data (can be NULL for checking size)
  //  * \param dlen     size of the data
  //  * \param sign     signature
  //  * \param slen     size of the signature
  //  * \param key      encryption key
  //  *
  //  * \return         0 if successful, or an error code
  //  */
  // extern int verifyStringRSA_SHA256(const char *data, const unsigned long dlen,
  //                                   const char *sign, const unsigned long slen,
  //                                   const AtEncryptionKey *key);
#ifdef __cplusplus
}
#endif
