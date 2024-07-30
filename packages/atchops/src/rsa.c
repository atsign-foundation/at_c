#include "atchops/rsa.h"
#include "atchops/rsa_key.h"
#include "atchops/sha.h"
#include "atlogger/atlogger.h"
#include "atchops/mbedtls.h"
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define TAG "rsa"

int atchops_rsa_sign(const atchops_rsa_key_private_key *private_key, const atchops_md_type md_type,
                     const unsigned char *message, const size_t message_len, unsigned char *signature) {
  int ret = 1;

  /*
   * 1. Validate arguments
   */
  if (private_key == NULL) {
    ret = 1;
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "private_key is NULL\n");
    return ret;
  }

  if (md_type != ATCHOPS_MD_SHA256) {
    ret = 1;
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "Unsupported hash type for rsa sign\n");
    return ret;
  }

  if (message == NULL) {
    ret = 1;
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "message is NULL\n");
    return ret;
  }

  if (message_len <= 0) {
    ret = 1;
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "message_len is less than or equal to 0\n");
    return ret;
  }

  /*
   * 2. Variables
   */
  size_t hashsize;

  if (md_type == ATCHOPS_MD_SHA256) {
    hashsize = 32; // TODO: constant
  }

  unsigned char hash[hashsize];
  memset(hash, 0, sizeof(unsigned char) * hashsize);

  mbedtls_rsa_context rsa;
  mbedtls_rsa_init(&rsa);

  mbedtls_entropy_context entropy_ctx;
  mbedtls_entropy_init(&entropy_ctx);

  mbedtls_ctr_drbg_context ctr_drbg_ctx;
  mbedtls_ctr_drbg_init(&ctr_drbg_ctx);

  /*
   * 3. Hash the message
   */
  if ((ret = atchops_sha_hash(md_type, message, message_len, hash)) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "Failed to perform for sha hash for rsa signing\n");
    goto ret;
  }

  /*
   * 4. Prepare RSA context
   */
  if ((ret = mbedtls_rsa_import_raw(&rsa, private_key->n.value, private_key->n.len, private_key->p.value,
                                    private_key->p.len, private_key->q.value, private_key->q.len, private_key->d.value,
                                    private_key->d.len, private_key->e.value, private_key->e.len)) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "Failed to do mbedtls_rsa_import_raw signing\n");
    goto ret;
  }

  if ((ret = mbedtls_rsa_complete(&rsa)) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "Failed to do mbedtls_rsa_complete operation\n");
    goto ret;
  }

  if ((ret = mbedtls_rsa_check_privkey(&rsa)) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "Failed to do mbedtls_rsa_check_privkey operation\n");
    goto ret;
  }

  if ((ret = mbedtls_ctr_drbg_seed(&ctr_drbg_ctx, mbedtls_entropy_func, &entropy_ctx, NULL, 0)) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "Failed to do mbedtls_ctr_drbg_seed operation\n");
    goto ret;
  }

  /*
   * 5. Sign the hash with RSA private key
   */
  if ((ret = mbedtls_rsa_pkcs1_sign(&rsa, mbedtls_ctr_drbg_random, &ctr_drbg_ctx, atchops_mbedtls_md_map[md_type],
                                    hashsize, hash, signature)) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "Failed to do mbedtls_rsa_pkcs1_sign operation\n");
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

int atchops_rsa_verify(const atchops_rsa_key_public_key *public_key, const atchops_md_type md_type,
                       const unsigned char *message, const size_t message_len, unsigned char *signature) {
  int ret = 1;

  /*
   * 1. Validate arguments
   */
  if (public_key == NULL) {
    ret = 1;
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "public_key is NULL\n");
    return ret;
  }

  if (md_type != ATCHOPS_MD_SHA256) {
    ret = 1;
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "Unsupported hash type for rsa verify\n");
    return ret;
  }

  if (message == NULL) {
    ret = 1;
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "message is NULL\n");
    return ret;
  }

  if (message_len <= 0) {
    ret = 1;
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "message_len is less than or equal to 0\n");
    return ret;
  }

  if (signature == NULL) {
    ret = 1;
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "signature is NULL\n");
    return ret;
  }

  /*
   * 2. Variables
   */
  size_t hashsize;

  if (md_type == ATCHOPS_MD_SHA256) {
    hashsize = 32;
  }

  unsigned char hash[hashsize];
  memset(hash, 0, sizeof(unsigned char) * hashsize);

  mbedtls_rsa_context rsa;
  mbedtls_rsa_init(&rsa);

  /*
   * 3. Prepare RSA context
   */
  if ((ret = mbedtls_rsa_import_raw(&rsa, public_key->n.value, public_key->n.len, NULL, 0, NULL, 0, NULL, 0,
                                    public_key->e.value, public_key->e.len)) != 0) {
    goto exit;
  }

  if (mbedtls_rsa_complete(&rsa) != 0 || mbedtls_rsa_check_pubkey(&rsa) != 0) {
    goto exit;
  }

  /*
   * 4. Hash the message
   */
  if ((ret = atchops_sha_hash(md_type, message, message_len, hash) != 0)) {
    goto exit;
  }

  /*
   * 5. Verify the signature with RSA public key
   */
  if ((ret = mbedtls_rsa_pkcs1_verify(&rsa, atchops_mbedtls_md_map[md_type], hashsize, hash, signature)) != 0) {
    goto exit;
  }

  ret = 0;
  goto exit;
exit: {
  mbedtls_rsa_free(&rsa);
  return ret;
}
}

int atchops_rsa_encrypt(const atchops_rsa_key_public_key *public_key, const unsigned char *plaintext,
                        const size_t plaintext_len, unsigned char *ciphertext) {
  int ret = 1;

  /*
   * 1. Validate arguments
   */

  if (public_key == NULL) {
    ret = 1;
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "public_key is NULL\n");
    return ret;
  }

  if (plaintext == NULL) {
    ret = 1;
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "plaintext is NULL\n");
    return ret;
  }

  if (plaintext_len <= 0) {
    ret = 1;
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "plaintext_len is less than or equal to 0\n");
    return ret;
  }

  if (ciphertext == NULL) {
    ret = 1;
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "ciphertext is NULL\n");
    return ret;
  }

  /*
   * 2. Variables
   */
  mbedtls_rsa_context rsa;
  mbedtls_rsa_init(&rsa);

  mbedtls_entropy_context entropy_ctx;
  mbedtls_entropy_init(&entropy_ctx);

  mbedtls_ctr_drbg_context ctr_drbg_ctx;
  mbedtls_ctr_drbg_init(&ctr_drbg_ctx);

  /*
   * 3. Prepare RSA context
   */
  if ((ret = mbedtls_rsa_import_raw(&rsa, public_key->n.value, public_key->n.len, NULL, -1, NULL, -1, NULL, -1,
                                    public_key->e.value, public_key->e.len)) != 0) {
    goto exit;
  }

  if ((ret = mbedtls_rsa_check_pubkey(&rsa)) != 0) {
    goto exit;
  }

  if ((ret = mbedtls_rsa_complete(&rsa)) != 0) {
    goto exit;
  }

  if ((ret = mbedtls_ctr_drbg_seed(&ctr_drbg_ctx, mbedtls_entropy_func, &entropy_ctx, NULL, 0)) != 0) {
    goto exit;
  }

  /*
   * 4. Encrypt the plaintext with RSA public key
   */
  if ((ret = mbedtls_rsa_pkcs1_encrypt(&rsa, mbedtls_ctr_drbg_random, &ctr_drbg_ctx, plaintext_len, plaintext,
                                       ciphertext)) != 0) {
    goto exit;
  }

  ret = 0;
  goto exit;
exit: {
  mbedtls_rsa_free(&rsa);
  mbedtls_ctr_drbg_free(&ctr_drbg_ctx);
  mbedtls_entropy_free(&entropy_ctx);
  return ret;
}
}

int atchops_rsa_decrypt(const atchops_rsa_key_private_key *private_key, const unsigned char *ciphertext,
                        const size_t ciphertext_len, unsigned char *plaintext, const size_t plaintextsize,
                        size_t *plaintext_len) {
  int ret = 1;

  /*
   * 1. Validate arguments
   */
  if (private_key == NULL) {
    ret = 1;
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "private_key is NULL\n");
    return ret;
  }

  if (ciphertext == NULL) {
    ret = 1;
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "ciphertext is NULL\n");
    return ret;
  }

  if (ciphertext_len <= 0) {
    ret = 1;
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "ciphertext_len is less than or equal to 0\n");
    return ret;
  }

  if (plaintext == NULL) {
    ret = 1;
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "plaintext is NULL\n");
    return ret;
  }

  if (plaintextsize <= 0) {
    ret = 1;
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "plaintextsize is less than or equal to 0\n");
    return ret;
  }

  /*
   * 2. Variables
   */
  mbedtls_entropy_context entropy_ctx;
  mbedtls_entropy_init(&entropy_ctx);

  mbedtls_ctr_drbg_context ctr_drbg_ctx;
  mbedtls_ctr_drbg_init(&ctr_drbg_ctx);

  mbedtls_rsa_context rsa;
  mbedtls_rsa_init(&rsa);

  /*
   * 3. Prepare RSA context
   */
  if ((ret = mbedtls_rsa_import_raw(&rsa, private_key->n.value, private_key->n.len, private_key->p.value,
                                    private_key->p.len, private_key->q.value, private_key->q.len, private_key->d.value,
                                    private_key->d.len, private_key->e.value, private_key->e.len)) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "Failed to do mbedtls_rsa_import_raw operation\n");
    goto exit;
  }

  if ((ret = mbedtls_rsa_complete(&rsa)) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "Failed to do mbedtls_rsa_complete operation\n");
    goto exit;
  }

  if ((ret = mbedtls_rsa_check_privkey(&rsa)) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "Failed to do mbedtls_rsa_check_privkey operation\n");
    goto exit;
  }

  if ((ret = mbedtls_ctr_drbg_seed(&ctr_drbg_ctx, mbedtls_entropy_func, &entropy_ctx, NULL, 0)) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "Failed to do mbedtls_ctr_drbg_seed operation\n");
    goto exit;
  }

  /*
   * 4. Decrypt the ciphertext with RSA private key
   */
  size_t olen;
  if ((ret = mbedtls_rsa_pkcs1_decrypt(&rsa, mbedtls_ctr_drbg_random, &ctr_drbg_ctx, &olen, ciphertext, plaintext,
                                       plaintextsize)) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "Failed to do mbedtls_rsa_pkcs1_decrypt operation\n");
    goto exit;
  }

  /*
   * 5. Set the length of the plaintext
   */
  if (plaintext_len != NULL) {
    *plaintext_len = olen;
  }

  ret = 0;
  goto exit;
exit: {
  mbedtls_rsa_free(&rsa);
  mbedtls_ctr_drbg_free(&ctr_drbg_ctx);
  mbedtls_entropy_free(&entropy_ctx);
  return ret;
}
}

int atchops_rsa_generate(atchops_rsa_key_public_key *public_key, atchops_rsa_key_private_key *private_key,
                         const unsigned int key_size) {
  // TODO maybe also introduce `enum atchops_rsa_key_size` ?
  return 1; // TODO: implement
}
