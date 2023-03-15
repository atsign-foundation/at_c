#ifdef BUILD_MBEDTLS
#ifdef __cplusplus
extern "C"
{
#endif

#include "at_chops.h"

#include <mbedtls/aes.h>
#include <mbedtls/base64.h>
#include <mbedtls/entropy.h>
#include <mbedtls/ctr_drbg.h>
#include <mbedtls/pk.h>
#include <mbedtls/rsa.h>

  // Base64 Encode and Decode
  int base64Encode(unsigned char *dst, unsigned long dlen, unsigned long *olen,
                   const unsigned char *src, unsigned long slen)
  {
    return mbedtls_base64_encode(dst, dlen, olen, src, slen);
  }

  int base64Decode(unsigned char *dst, unsigned long dlen, unsigned long *olen,
                   const unsigned char *src, unsigned long slen)
  {
    return mbedtls_base64_decode(dst, dlen, olen, src, slen);
  }

  // Encryption and Decryption - AES
  int initContextAES(AtEncryptionContext *ctx, const AtEncryptionKey *key);
  int decryptBytesAES(unsigned char *dst, const unsigned long dlen, unsigned long *olen,
                      const unsigned char *src, const unsigned long slen,
                      const AtEncryptionKey *key,
                      const InitialisationVector *iv);
  int decryptStringAES(char *dst, const unsigned long dlen, unsigned long *olen,
                       const char *src, const unsigned long slen,
                       const AtEncryptionKey *key,
                       const InitialisationVector *iv);
  int encryptBytesAES(unsigned char *dst, const unsigned long dlen, unsigned long *olen,
                      const unsigned char *src, const unsigned long slen,
                      const AtEncryptionKey *key);
  int encryptStringAES(char *dst, const unsigned long dlen, unsigned long *olen,
                       const char *src, const unsigned long slen,
                       const AtEncryptionKey *key);

  // Encryption and Decryption - RSA
  int initContextRSA(AtEncryptionContext *ctx, const AtEncryptionKey *key,
                     const unsigned char *pwd, unsigned long pwdlen,
                     int (*f_rng)(void *, unsigned char *, unsigned long), void *p_rng)
  {
    int retval;

    // Entropy and RNG
    mbedtls_entropy_context entropy;
    mbedtls_ctr_drbg_context ctr_drbg;
    unsigned char use_default_rng = (f_rng == NULL) || (p_rng == NULL);

    // Base64 decoded key
    unsigned char *decoded_key;
    unsigned long dlen, olen;

    // Private/Public Key and RSA context
    mbedtls_pk_context pk;
    mbedtls_rsa_context rsa;

    // Get the size of the decoded key
    retval = base64Decode(decoded_key, dlen, &olen,
                          (const unsigned char *)key->key, key->size);
    if (retval != 0)
      return retval;

    // Decode the key to the buffer
    dlen = olen;
    retval = base64Decode(decoded_key, dlen, &olen,
                          (const unsigned char *)key->key, key->size);
    if (retval != 0)
      return retval;

    if (use_default_rng)
    {
      // Initialise the entropy and rng
      mbedtls_entropy_init(&entropy);
      mbedtls_ctr_drbg_init(&ctr_drbg);

      // Seed the rng with entropy source
      retval = mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func,
                                     &entropy, NULL, 0);

      if (retval != 0)
        return retval;
    }

    // Init a public or private key
    mbedtls_pk_init(&pk);

    if (use_default_rng)
    {
      f_rng = mbedtls_ctr_drbg_random;
      p_rng = &ctr_drbg;
    }

    retval = mbedtls_pk_parse_key(&pk, decoded_key, dlen,
                                  pwd, pwdlen,
                                  f_rng, p_rng);
    if (retval != 0)
      return retval;

    if (mbedtls_pk_get_type(&pk) != MBEDTLS_PK_RSA)
      return MBEDTLS_ERR_PK_TYPE_MISMATCH;

    // Create a new RSA context
    mbedtls_rsa_init(&rsa);

    // Copy the key into the RSA context
    rsa = *mbedtls_pk_rsa(pk);

    // Free the key
    mbedtls_pk_free(&pk);

    // Store the RSA context into the encryption context
    ctx->header = key->header;
    ctx->size = sizeof(mbedtls_rsa_context);
    ctx->ctx = &rsa;

    // Free entropy and rng if it was used
    if (use_default_rng)
    {
      mbedtls_ctr_drbg_free(&ctr_drbg);
      mbedtls_entropy_free(&entropy);
    }
  }

  int initContextFromFileRSA(AtEncryptionContext *ctx, const char *path,
                             const unsigned char *pwd, unsigned char key_type,
                             int (*f_rng)(void *, unsigned char *, unsigned long), void *p_rng)
  {
    int retval;

    // Entropy and RNG
    mbedtls_entropy_context entropy;
    mbedtls_ctr_drbg_context ctr_drbg;
    unsigned char use_default_rng = (f_rng == NULL) || (p_rng == NULL);

    // Private/Public Key and RSA context
    mbedtls_pk_context pk;
    mbedtls_rsa_context rsa;

    if (use_default_rng)
    {
      // Initialise the entropy and rng
      mbedtls_entropy_init(&entropy);
      mbedtls_ctr_drbg_init(&ctr_drbg);

      // Seed the rng with entropy source
      retval = mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func,
                                     &entropy, NULL, 0);

      if (retval != 0)
        return retval;
    }

    // Init a public or private key
    mbedtls_pk_init(&pk);

    if (use_default_rng)
    {
      f_rng = mbedtls_ctr_drbg_random;
      p_rng = &ctr_drbg;
    }

    retval = mbedtls_pk_parse_keyfile(&pk, path, pwd, f_rng, p_rng);
    if (retval != 0)
      return retval;

    if (mbedtls_pk_get_type(&pk) != MBEDTLS_PK_RSA)
      return MBEDTLS_ERR_PK_TYPE_MISMATCH;

    // Create a new RSA context
    mbedtls_rsa_init(&rsa);

    // Copy the key into the RSA context
    rsa = *mbedtls_pk_rsa(pk);

    // Free the key
    mbedtls_pk_free(&pk);

    // Store the RSA context into the encryption context
    ctx->header = key_type;
    ctx->size = sizeof(mbedtls_rsa_context);
    ctx->ctx = &rsa;

    // Free entropy and rng if it was used
    if (use_default_rng)
    {
      mbedtls_ctr_drbg_free(&ctr_drbg);
      mbedtls_entropy_free(&entropy);
    }
  }

  int decryptBytesRSA(unsigned char *dst, const unsigned long dlen, unsigned long *olen,
                      const unsigned char *src, const unsigned long slen,
                      const AtEncryptionKey *key)
  {
  }
  int decryptStringRSA(char *dst, const unsigned long dlen, unsigned long *olen,
                       const char *src, const unsigned long slen,
                       const AtEncryptionKey *key)
  {
    return decryptBytesRSA((unsigned char *)dst, dlen, olen, (const unsigned char *)src, slen, key);
  }
  int encryptBytesRSA(unsigned char *dst, const unsigned long dlen, unsigned long *olen,
                      const unsigned char *src, const unsigned long slen,
                      const AtEncryptionKey *key);
  int encryptStringRSA(char *dst, const unsigned long dlen, unsigned long *olen,
                       const char *src, const unsigned long slen,
                       const AtEncryptionKey *key)
  {
    return encryptBytesRSA((unsigned char *)dst, dlen, olen, (const unsigned char *)src, slen, key);
  }

  // Hashing
  int hashSHA512(unsigned char *dst, const unsigned long dlen, unsigned long *olen,
                 const unsigned char *src, const unsigned long slen);

  // Signing and Verification - RSA/SHA256
  int signBytesRSA_SHA256(unsigned char *dst, const unsigned long dlen, unsigned long *olen,
                          const unsigned char *src, const unsigned long slen,
                          const AtEncryptionKey *key);
  int signStringRSA_SHA256(char *dst, const unsigned long dlen, unsigned long *olen,
                           const char *src, const unsigned long slen,
                           const AtEncryptionKey *key);
  int verifyBytesRSA_SHA256(const unsigned char *data, const unsigned long dlen,
                            const unsigned char *sign, const unsigned long slen,
                            const AtEncryptionKey *key);
  int verifyStringRSA_SHA256(const char *data, const unsigned long dlen,
                             const char *sign, const unsigned long slen,
                             const AtEncryptionKey *key);

#ifdef __cplusplus
}
#endif
#endif
