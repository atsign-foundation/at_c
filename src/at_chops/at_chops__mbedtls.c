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
#include <string.h>
#include <stdlib.h>

  // Base64 Encode and Decode
  int base64_encode(unsigned char *dst, unsigned long dlen, unsigned long *olen,
                    const unsigned char *src, unsigned long slen)
  {
    return mbedtls_base64_encode(dst, dlen, olen, src, slen);
  }

  int base64_decode(unsigned char *dst, unsigned long dlen, unsigned long *olen,
                    const unsigned char *src, unsigned long slen)
  {
    return mbedtls_base64_decode(dst, dlen, olen, src, slen);
  }

  // Encryption and Decryption - AES
  int init_context_aes(AtEncryptionContext *ctx, const AtEncryptionKey *key)
  {
    // TODO remove this later
    unsigned char *decoded_key;
    unsigned long klen;
    unsigned long *kolen;

    int retval = base64_decode(decoded_key, klen, kolen, (const unsigned char *)key->key, key->size);
    if (retval != 0)
      return retval;

    mbedtls_aes_context *aes = malloc(sizeof(mbedtls_aes_context));
    mbedtls_aes_init(aes);

    unsigned int keybits = ((unsigned int)*kolen * sizeof(decoded_key));
    retval = mbedtls_aes_setkey_enc(aes, decoded_key, keybits);
    if (retval != 0)
      return retval;

    ctx->ctx = aes;

    return 0;
  }

  int decrypt_bytes_aes_ctr(unsigned char *dst,
                            unsigned long dlen,
                            unsigned long *olen,
                            const unsigned char *src,
                            const unsigned long slen,
                            const AtEncryptionKey *key,
                            const InitialisationVector *iv)
  {
    int retval;

    // Initialize AES context
    mbedtls_aes_context ctx;
    mbedtls_aes_init(&ctx);

    // AES Key Decoding
    unsigned char *decoded_key;
    unsigned long klen;
    unsigned long *kolen;

    // AES IV
    unsigned long nc_off = 0;
    unsigned char nc[16] = {0};
    unsigned char sb[16];
    for (int i = 0; i < iv->len; i++)
    {
      nc[i] = iv->iv[i];
    }

    // Decode key
    retval = base64_decode(decoded_key, klen, kolen, (const unsigned char *)key->key, key->size);
    if (retval != 0)
    {
      mbedtls_aes_free(&ctx);
      return retval;
    }

    unsigned int keybits = ((unsigned int)*kolen * sizeof(decoded_key));
    retval = mbedtls_aes_setkey_dec(&ctx, decoded_key, keybits);
    if (retval != 0)
    {
      mbedtls_aes_free(&ctx);
      return retval;
    }

    unsigned long size = slen * sizeof(char);
    unsigned char decoded_bytes[size];

    retval = base64_decode(decoded_bytes, dlen, olen, src, slen);
    if (retval != 0)
      return retval;
    printf("a");
    dst = (unsigned char *)malloc(*olen);
    retval = mbedtls_aes_crypt_ctr(&ctx, *olen, &nc_off, nc, sb, decoded_bytes, dst);

    if (retval != 0)
    {
      mbedtls_aes_free(&ctx);
      return retval;
    }

    mbedtls_aes_free(&ctx);
    return 0;
  }

  int decrypt_string_aes_ctr(char *dst, unsigned long dlen,
                             unsigned long *olen,
                             const char *src,
                             const unsigned long slen,
                             const AtEncryptionKey *key,
                             const InitialisationVector *iv)
  {
    return decrypt_bytes_aes_ctr((unsigned char *)dst, dlen, olen, (const unsigned char *)src, slen, key, iv);
  }

  int encrypt_bytes_aes_ctr(unsigned char *dst,
                            unsigned long dlen,
                            unsigned long *olen,
                            const unsigned char *src,
                            const unsigned long slen,
                            const AtEncryptionKey *key,
                            InitialisationVector *iv)
  {
    int retval;

    // AES/RNG/Entropy Context
    mbedtls_aes_context *ctx = malloc(sizeof(mbedtls_aes_context));
    mbedtls_ctr_drbg_context ctr_drbg;
    mbedtls_entropy_context entropy;

    // AES Key decoding
    unsigned char *decoded_key;
    unsigned long klen;
    unsigned long *kolen;

    // AES IV
    unsigned long nc_off = 0;
    unsigned char nc[16] = {0};
    iv->len = 16; // Must be same size as nc
    unsigned char sb[16];

    // Initialise the contexts
    mbedtls_aes_init(ctx);
    mbedtls_ctr_drbg_init(&ctr_drbg);
    mbedtls_entropy_init(&entropy);

    printf("a");
    // Seed the rng with entropy source
    retval = mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func,
                                   &entropy, NULL, 0);
    if (retval != 0)
    {
      mbedtls_aes_free(ctx);
      mbedtls_ctr_drbg_free(&ctr_drbg);
      mbedtls_entropy_free(&entropy);
      return retval;
    }

    printf("b");

    // Decode the AES Key
    retval = base64_decode(decoded_key, klen, kolen, (const unsigned char *)key->key, key->size);
    if (retval != 0)
    {
      mbedtls_aes_free(ctx);
      mbedtls_ctr_drbg_free(&ctr_drbg);
      mbedtls_entropy_free(&entropy);
      return retval;
    }

    printf("c");

    // Set the AES key in context
    unsigned int keybits = ((unsigned int)*kolen * sizeof(decoded_key));
    retval = mbedtls_aes_setkey_enc(ctx, decoded_key, keybits);
    if (retval != 0)
    {
      mbedtls_aes_free(ctx);
      mbedtls_ctr_drbg_free(&ctr_drbg);
      mbedtls_entropy_free(&entropy);
      return retval;
    }

    // Initialise the byte buffer and size
    unsigned long ssize = slen * sizeof(src);
    unsigned char encrypted_bytes[ssize];

    // Encrypt the bytes
    retval = mbedtls_aes_crypt_ctr(ctx, ssize, &nc_off, nc, sb, src, encrypted_bytes);
    if (retval != 0)
    {
      mbedtls_aes_free(ctx);
      mbedtls_ctr_drbg_free(&ctr_drbg);
      mbedtls_entropy_free(&entropy);
      return retval;
    }

    // Encode the encrypted bytes
    retval = base64_encode(dst, dlen, olen, encrypted_bytes, ssize);
    if (retval != 0)
    {
      mbedtls_aes_free(ctx);
      mbedtls_ctr_drbg_free(&ctr_drbg);
      mbedtls_entropy_free(&entropy);
      return retval;
    }

    // Copy the nonce counter to iv
    iv->iv = nc;

    mbedtls_aes_free(ctx);
    mbedtls_ctr_drbg_free(&ctr_drbg);
    mbedtls_entropy_free(&entropy);
    return 0;
  }

  int encrypt_string_aes_ctr(char *dst,
                             unsigned long dlen,
                             unsigned long *olen,
                             const char *src,
                             const unsigned long slen,
                             const AtEncryptionKey *key,
                             InitialisationVector *iv)
  {
    return encrypt_bytes_aes_ctr((unsigned char *)dst, dlen, olen, (const unsigned char *)src, slen, key, iv);
  }

  // // Encryption and Decryption - RSA
  // int initContextRSA(AtEncryptionContext *ctx, const AtEncryptionKey *key,
  //                    const unsigned char *pwd, unsigned long pwdlen,
  //                    int (*f_rng)(void *, unsigned char *, unsigned long), void *p_rng)
  // {
  //   int retval;

  //   // Entropy and RNG
  //   mbedtls_entropy_context entropy;
  //   mbedtls_ctr_drbg_context ctr_drbg;
  //   unsigned char use_default_rng = (f_rng == NULL) || (p_rng == NULL);

  //   // Base64 decoded key
  //   unsigned char *decoded_key;
  //   unsigned long dlen, olen;

  //   // Private/Public Key and RSA context
  //   mbedtls_pk_context pk;
  //   mbedtls_rsa_context rsa;

  //   // Get the size of the decoded key
  //   retval = base64Decode(decoded_key, dlen, &olen,
  //                         (const unsigned char *)key->key, key->size);
  //   if (retval != 0)
  //     return retval;

  //   // Decode the key to the buffer
  //   dlen = olen;
  //   retval = base64Decode(decoded_key, dlen, &olen,
  //                         (const unsigned char *)key->key, key->size);
  //   if (retval != 0)
  //     return retval;

  //   if (use_default_rng)
  //   {
  //     // Initialise the entropy and rng
  //     mbedtls_entropy_init(&entropy);
  //     mbedtls_ctr_drbg_init(&ctr_drbg);

  //     // Seed the rng with entropy source
  //     retval = mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func,
  //                                    &entropy, NULL, 0);

  //     if (retval != 0)
  //       return retval;
  //   }

  //   // Init a public or private key
  //   mbedtls_pk_init(&pk);

  //   if (use_default_rng)
  //   {
  //     f_rng = mbedtls_ctr_drbg_random;
  //     p_rng = &ctr_drbg;
  //   }

  //   retval = mbedtls_pk_parse_key(&pk, decoded_key, dlen,
  //                                 pwd, pwdlen,
  //                                 f_rng, p_rng);
  //   if (retval != 0)
  //     return retval;

  //   if (mbedtls_pk_get_type(&pk) != MBEDTLS_PK_RSA)
  //     return MBEDTLS_ERR_PK_TYPE_MISMATCH;

  //   // Create a new RSA context
  //   mbedtls_rsa_init(&rsa);

  //   // Copy the key into the RSA context
  //   rsa = *mbedtls_pk_rsa(pk);

  //   // Free the key
  //   mbedtls_pk_free(&pk);

  //   // Store the RSA context into the encryption context
  //   ctx->header = key->header;
  //   ctx->size = sizeof(mbedtls_rsa_context);
  //   ctx->ctx = &rsa;

  //   // Free entropy and rng if it was used
  //   if (use_default_rng)
  //   {
  //     mbedtls_ctr_drbg_free(&ctr_drbg);
  //     mbedtls_entropy_free(&entropy);
  //   }
  // }

  // int initContextFromFileRSA(AtEncryptionContext *ctx, const char *path,
  //                            const unsigned char *pwd, unsigned char key_type,
  //                            int (*f_rng)(void *, unsigned char *, unsigned long), void *p_rng)
  // {
  //   int retval;

  //   // Entropy and RNG
  //   mbedtls_entropy_context entropy;
  //   mbedtls_ctr_drbg_context ctr_drbg;
  //   unsigned char use_default_rng = (f_rng == NULL) || (p_rng == NULL);

  //   // Private/Public Key and RSA context
  //   mbedtls_pk_context pk;
  //   mbedtls_rsa_context rsa;

  //   if (use_default_rng)
  //   {
  //     // Initialise the entropy and rng
  //     mbedtls_entropy_init(&entropy);
  //     mbedtls_ctr_drbg_init(&ctr_drbg);

  //     // Seed the rng with entropy source
  //     retval = mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func,
  //                                    &entropy, NULL, 0);

  //     if (retval != 0)
  //       return retval;
  //   }

  //   // Init a public or private key
  //   mbedtls_pk_init(&pk);

  //   if (use_default_rng)
  //   {
  //     f_rng = mbedtls_ctr_drbg_random;
  //     p_rng = &ctr_drbg;
  //   }

  //   retval = mbedtls_pk_parse_keyfile(&pk, path, pwd, f_rng, p_rng);
  //   if (retval != 0)
  //     return retval;

  //   if (mbedtls_pk_get_type(&pk) != MBEDTLS_PK_RSA)
  //     return MBEDTLS_ERR_PK_TYPE_MISMATCH;

  //   // Create a new RSA context
  //   mbedtls_rsa_init(&rsa);

  //   // Copy the key into the RSA context
  //   rsa = *mbedtls_pk_rsa(pk);

  //   // Free the key
  //   mbedtls_pk_free(&pk);

  //   // Store the RSA context into the encryption context
  //   ctx->header = key_type;
  //   ctx->size = sizeof(mbedtls_rsa_context);
  //   ctx->ctx = &rsa;

  //   // Free entropy and rng if it was used
  //   if (use_default_rng)
  //   {
  //     mbedtls_ctr_drbg_free(&ctr_drbg);
  //     mbedtls_entropy_free(&entropy);
  //   }
  // }

  // int decryptBytesRSA(unsigned char *dst, const unsigned long dlen, unsigned long *olen,
  //                     const unsigned char *src, const unsigned long slen,
  //                     const AtEncryptionKey *key)
  // {
  // }
  // int decryptStringRSA(char *dst, const unsigned long dlen, unsigned long *olen,
  //                      const char *src, const unsigned long slen,
  //                      const AtEncryptionKey *key)
  // {
  //   return decryptBytesRSA((unsigned char *)dst, dlen, olen, (const unsigned char *)src, slen, key);
  // }
  // int encryptBytesRSA(unsigned char *dst, const unsigned long dlen, unsigned long *olen,
  //                     const unsigned char *src, const unsigned long slen,
  //                     const AtEncryptionKey *key);
  // int encryptStringRSA(char *dst, const unsigned long dlen, unsigned long *olen,
  //                      const char *src, const unsigned long slen,
  //                      const AtEncryptionKey *key)
  // {
  //   return encryptBytesRSA((unsigned char *)dst, dlen, olen, (const unsigned char *)src, slen, key);
  // }

  // // Hashing
  // int hashSHA512(unsigned char *dst, const unsigned long dlen, unsigned long *olen,
  //                const unsigned char *src, const unsigned long slen);

  // // Signing and Verification - RSA/SHA256
  // int signBytesRSA_SHA256(unsigned char *dst, const unsigned long dlen, unsigned long *olen,
  //                         const unsigned char *src, const unsigned long slen,
  //                         const AtEncryptionKey *key);
  // int signStringRSA_SHA256(char *dst, const unsigned long dlen, unsigned long *olen,
  //                          const char *src, const unsigned long slen,
  //                          const AtEncryptionKey *key);
  // int verifyBytesRSA_SHA256(const unsigned char *data, const unsigned long dlen,
  //                           const unsigned char *sign, const unsigned long slen,
  //                           const AtEncryptionKey *key);
  // int verifyStringRSA_SHA256(const char *data, const unsigned long dlen,
  //                            const char *sign, const unsigned long slen,
  //                            const AtEncryptionKey *key);

#ifdef __cplusplus
}
#endif
#endif
