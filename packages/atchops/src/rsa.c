#include "atchops/rsa.h"
#include "atchops/base64.h"
#include "atchops/rsakey.h"
#include "atchops/sha.h"
#include <mbedtls/asn1.h>
#include <mbedtls/ctr_drbg.h>
#include <mbedtls/entropy.h>
#include <mbedtls/md.h>
#include <mbedtls/md5.h>
#include <mbedtls/rsa.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stddef.h>

int atchops_rsa_sign(atchops_rsakey_privatekey privatekey, mbedtls_md_type_t mdtype, const unsigned char *message,
                     const size_t messagelen, unsigned char *signaturebase64,
                     const size_t signaturebase64len, size_t *signaturebase64olen) {
  int ret = 1; // error, until successful.

  const size_t hashlen = 32;
  unsigned char *hash = malloc(sizeof(unsigned char) * hashlen);
  memset(hash, 0, hashlen);
  size_t hasholen = 0;

  mbedtls_rsa_context rsa;
  mbedtls_rsa_init(&rsa);

  mbedtls_entropy_context entropy_ctx;
  mbedtls_entropy_init(&entropy_ctx);

  mbedtls_ctr_drbg_context ctr_drbg_ctx;
  mbedtls_ctr_drbg_init(&ctr_drbg_ctx);

  const size_t signaturelen = 256; // result of signature always 256 bytes
  unsigned char *signature = malloc(sizeof(unsigned char) * signaturelen);
  memset(signature, 0, signaturelen);

  // 1. hash the message
  ret = atchops_sha_hash(mdtype, message, messagelen, hash, hashlen, &hasholen);
  // printf("atchops_sha_hash: %d\n", ret);
  if (ret != 0) {
    goto ret;
  }

  // 2. sign the hash with rsa private key
  ret = mbedtls_rsa_import_raw(&rsa, privatekey.n.value, privatekey.n.len, privatekey.p.value, privatekey.p.len,
                               privatekey.q.value, privatekey.q.len, privatekey.d.value, privatekey.d.len,
                               privatekey.e.value, privatekey.e.len);
  if (ret != 0) {
    goto ret;
  }

  ret = mbedtls_rsa_complete(&rsa);
  if (ret != 0) {
    goto ret;
  }

  ret = mbedtls_rsa_check_privkey(&rsa);
  if (ret != 0) {
    goto ret;
  }

  ret = mbedtls_ctr_drbg_seed(&ctr_drbg_ctx, mbedtls_entropy_func, &entropy_ctx, NULL, 0);
  if (ret != 0) {
    goto ret;
  }

  ret =
      mbedtls_rsa_pkcs1_sign(&rsa, mbedtls_ctr_drbg_random, &ctr_drbg_ctx, MBEDTLS_MD_SHA256, hashlen, hash, signature);
  if (ret != 0) {
    goto ret;
  }

  // 3. base64 encode the signature
  ret = atchops_base64_encode(signature, signaturelen, signaturebase64, signaturebase64len, signaturebase64olen);
  if (ret != 0) {
    goto ret;
  }

  goto ret;

ret: {
  free(hash);
  free(signature);
  mbedtls_rsa_free(&rsa);
  mbedtls_ctr_drbg_free(&ctr_drbg_ctx);
  mbedtls_entropy_free(&entropy_ctx);
  return ret;
}
}

int atchops_rsa_verify(atchops_rsakey_publickey publickey, mbedtls_md_type_t mdtype, const unsigned char *signature,
                       const size_t signaturelen, int *result) {
  return 1; // TODO: implement
}

int atchops_rsa_encrypt(atchops_rsakey_publickey publickey, const unsigned char *plaintext,
                        const size_t plaintextlen, unsigned char *ciphertextbase64,
                        const size_t ciphertextbase64len, size_t *ciphertextbase64olen) {
  int ret = 1;

  mbedtls_rsa_context rsa;
  mbedtls_rsa_init(&rsa);

  mbedtls_entropy_context entropy_ctx;
  mbedtls_entropy_init(&entropy_ctx);

  mbedtls_ctr_drbg_context ctr_drbg_ctx;
  mbedtls_ctr_drbg_init(&ctr_drbg_ctx);

  const size_t outputlen = 256; // 256 bytes is the result of an RSA
  unsigned char *output = malloc(sizeof(unsigned char) * outputlen);
  memset(output, 0, outputlen);

  // 1. rsa encrypt the plain text
  ret = mbedtls_rsa_import_raw(&rsa, publickey.n.value, publickey.n.len, NULL, -1, NULL, -1, NULL, -1,
                               publickey.e.value, publickey.e.len);
  if (ret != 0) {
    goto exit;
  }

  ret = mbedtls_rsa_check_pubkey(&rsa);
  if (ret != 0) {
    goto exit;
  }

  ret = mbedtls_rsa_complete(&rsa);
  if (ret != 0) {
    goto exit;
  }

  ret = mbedtls_ctr_drbg_seed(&ctr_drbg_ctx, mbedtls_entropy_func, &entropy_ctx, NULL, 0);
  if (ret != 0) {
    goto exit;
  }

  ret = mbedtls_rsa_pkcs1_encrypt(&rsa, mbedtls_ctr_drbg_random, &ctr_drbg_ctx, plaintextlen, plaintext, output);
  if (ret != 0) {
    goto exit;
  }

  ret = atchops_base64_encode(output, outputlen, ciphertextbase64, ciphertextbase64len, ciphertextbase64olen);
  if (ret != 0) {
    goto exit;
  }

  goto exit;

exit: {
  mbedtls_rsa_free(&rsa);
  mbedtls_ctr_drbg_free(&ctr_drbg_ctx);
  mbedtls_entropy_free(&entropy_ctx);
  free(output);
  return ret;
}
}

int atchops_rsa_decrypt(atchops_rsakey_privatekey privatekey, const unsigned char *ciphertextbase64,
                        const size_t ciphertextbase64len, unsigned char *plaintext,
                        const size_t plaintextlen, size_t *plaintextolen) {
  int ret = 1;

    const size_t ciphertextlen = ciphertextbase64len; // the result of the base64 decode of the cipher text should be of sufficient length for the plaintext length they are expecting
    unsigned char *ciphertext = malloc(sizeof(unsigned char) * ciphertextlen);
    memset(ciphertext, 0, ciphertextlen);
    size_t ciphertextolen = 0;

  mbedtls_entropy_context entropy_ctx;
  mbedtls_entropy_init(&entropy_ctx);

  mbedtls_ctr_drbg_context ctr_drbg_ctx;
  mbedtls_ctr_drbg_init(&ctr_drbg_ctx);

  mbedtls_rsa_context rsa;
  mbedtls_rsa_init(&rsa);

  // 1. base64 decode the ciphertextbase64
  ret = atchops_base64_decode(ciphertextbase64, ciphertextbase64len, ciphertext, ciphertextlen, &ciphertextolen);
  if (ret != 0) {
    goto exit;
  }

  // 2. rsa decrypt the base64 decoded ciphertext
  ret = mbedtls_rsa_import_raw(&rsa, privatekey.n.value, privatekey.n.len, privatekey.p.value, privatekey.p.len,
                               privatekey.q.value, privatekey.q.len, privatekey.d.value, privatekey.d.len,
                               privatekey.e.value, privatekey.e.len);
  if (ret != 0) {
    goto exit;
  }

  ret = mbedtls_rsa_complete(&rsa);
  if (ret != 0) {
    goto exit;
  }

  ret = mbedtls_rsa_check_privkey(&rsa);
  if (ret != 0) {
    goto exit;
  }

  ret = mbedtls_ctr_drbg_seed(&ctr_drbg_ctx, mbedtls_entropy_func, &entropy_ctx, NULL, 0);
  if (ret != 0) {
    goto exit;
  }

  ret = mbedtls_rsa_pkcs1_decrypt(&rsa, mbedtls_ctr_drbg_random, &ctr_drbg_ctx, plaintextolen, ciphertext, plaintext,
                                  plaintextlen);
  if (ret != 0) {
    goto exit;
  }

  goto exit;

exit: {
  free(ciphertext);
  return ret;
}
}

int atchops_rsa_generate(atchops_rsakey_publickey *publickey, atchops_rsakey_privatekey *privatekey,
                         const unsigned int keysize) {
  return 1; // TODO: implement
}
