#include "atchops/rsa.h"
#include "atchops/rsakey.h"
#include "atchops/sha.h"
#include <mbedtls/asn1.h>
#include <mbedtls/ctr_drbg.h>
#include <mbedtls/entropy.h>
#include <mbedtls/md.h>
#include <mbedtls/md5.h>
#include <mbedtls/rsa.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int atchops_rsa_sign(const atchops_rsakey_privatekey privatekey, const mbedtls_md_type_t mdtype,
                     const unsigned char *message, const size_t messagelen, unsigned char *signature) {
  int ret = 1; // error, until successful.

  size_t hashsize;
  if (mdtype == MBEDTLS_MD_SHA256) {
    hashsize = 32;
  } else {
    // TODO: log error
    return 1; // unsupported hash type
  }

  unsigned char hash[hashsize];
  memset(hash, 0, sizeof(unsigned char) * hashsize);
  size_t hashlen = 0;

  mbedtls_rsa_context rsa;
  mbedtls_rsa_init(&rsa);

  mbedtls_entropy_context entropy_ctx;
  mbedtls_entropy_init(&entropy_ctx);

  mbedtls_ctr_drbg_context ctr_drbg_ctx;
  mbedtls_ctr_drbg_init(&ctr_drbg_ctx);

  // 1. hash the message
  ret = atchops_sha_hash(mdtype, message, messagelen, hash, hashsize, &hashlen);
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

  ret = mbedtls_rsa_pkcs1_sign(&rsa, mbedtls_ctr_drbg_random, &ctr_drbg_ctx, mdtype, hashsize, hash, signature);
  if (ret != 0) {
    goto ret;
  }

  goto ret;

ret: {
  mbedtls_rsa_free(&rsa);
  mbedtls_ctr_drbg_free(&ctr_drbg_ctx);
  mbedtls_entropy_free(&entropy_ctx);
  return ret;
}
}

int atchops_rsa_verify(atchops_rsakey_publickey publickey, mbedtls_md_type_t mdtype, const char *message,
                       const size_t messagelen, const unsigned char *signature, const unsigned long signaturelen) {
  int ret = 1;
  mbedtls_rsa_context rsa;

  size_t hashlen = 32;
  size_t hasholen;
  unsigned char hash[hashlen];

  size_t decoded_sig_len = 256;
  size_t decoded_sig_olen;
  unsigned char decoded_sig[decoded_sig_len];

  mbedtls_rsa_init(&rsa);
  if ((ret = mbedtls_rsa_import_raw(&rsa, publickey.n.value, publickey.n.len, NULL, 0, NULL, 0, NULL, 0,
                                    publickey.e.value, publickey.e.len)) != 0) {
    goto exit;
  }

  if (mbedtls_rsa_complete(&rsa) != 0 || mbedtls_rsa_check_pubkey(&rsa) != 0) {
    goto exit;
  }

  // compute the hash of the input message
  if ((ret = atchops_sha_hash(mdtype, (unsigned char *)message, messagelen, hash, hashlen, &hasholen)) != 0) {
    goto exit;
  }

  // decode the signature
  ret = atchops_base64_decode(signature, signaturelen, decoded_sig, decoded_sig_len, &decoded_sig_olen);
  if (ret != 0) {
    goto exit;
  }

  // verify the signature
  if ((ret = mbedtls_rsa_pkcs1_verify(&rsa, mdtype, hashlen, hash, decoded_sig)) != 0) {
    goto exit;
  }

  goto exit;

exit: {
  mbedtls_rsa_free(&rsa);
  return ret;
}
}

int atchops_rsa_encrypt(const atchops_rsakey_publickey publickey, const unsigned char *plaintext,
                        const size_t plaintextlen, unsigned char *ciphertext, const size_t ciphertextsize,
                        size_t *ciphertextlen) {
  int ret = 1;

  mbedtls_rsa_context rsa;
  mbedtls_rsa_init(&rsa);

  mbedtls_entropy_context entropy_ctx;
  mbedtls_entropy_init(&entropy_ctx);

  mbedtls_ctr_drbg_context ctr_drbg_ctx;
  mbedtls_ctr_drbg_init(&ctr_drbg_ctx);

  const size_t outputsize = 256; // 256 bytes is the result of a 2048-RSA modulus
  unsigned char output[outputsize];
  memset(output, 0, sizeof(unsigned char) * outputsize);

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

  goto exit;

exit: {
  mbedtls_rsa_free(&rsa);
  mbedtls_ctr_drbg_free(&ctr_drbg_ctx);
  mbedtls_entropy_free(&entropy_ctx);
  return ret;
}
}

int atchops_rsa_decrypt(const atchops_rsakey_privatekey privatekey, const unsigned char *ciphertext,
                        const size_t ciphertextlen, unsigned char *plaintext, const size_t plaintextsize,
                        size_t *plaintextlen) {
  int ret = 1;

  mbedtls_entropy_context entropy_ctx;
  mbedtls_entropy_init(&entropy_ctx);

  mbedtls_ctr_drbg_context ctr_drbg_ctx;
  mbedtls_ctr_drbg_init(&ctr_drbg_ctx);

  mbedtls_rsa_context rsa;
  mbedtls_rsa_init(&rsa);

  // 1. rsa decrypt the base64 decoded ciphertext
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

  ret = mbedtls_rsa_pkcs1_decrypt(&rsa, mbedtls_ctr_drbg_random, &ctr_drbg_ctx, plaintextlen, ciphertext, plaintext,
                                  plaintextsize);
  if (ret != 0) {
    goto exit;
  }

  goto exit;

exit: {
  mbedtls_rsa_free(&rsa);
  mbedtls_ctr_drbg_free(&ctr_drbg_ctx);
  mbedtls_entropy_free(&entropy_ctx);
  return ret;
}
}

int atchops_rsa_generate(atchops_rsakey_publickey *publickey, atchops_rsakey_privatekey *privatekey,
                         const unsigned int keysize) {
  return 1; // TODO: implement
}
