#include "atchops/ed25519.h"
#include "atchops/mbedtls.h"
#include "atchops/ed_key.h"
#include "atchops/sha.h"
#include "atlogger/atlogger.h"
#include <atchops/platform.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define TAG "ed25519"

int atchops_ed25519_sign(const atchops_ed25519_key_private_key *private_key, const unsigned char *message,
             const size_t message_len, unsigned char *signature) {
  int ret = 1;

  /*
   * 1. Validate arguments
   */
  if (private_key == NULL) {
  ret = 1;
  atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "private_key is NULL\n");
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
   * 2. Configure the hash function
   */
  mbedtls_md_context_t md_ctx;
  mbedtls_md_init(&md_ctx);

  const mbedtls_md_info_t *md_info = mbedtls_md_info_from_type(MBEDTLS_MD_SHA512);
  if (md_info == NULL) {
  atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "mbedtls_md_info_from_type failed\n");
  return 1;
  }

  if (mbedtls_md_setup(&md_ctx, md_info, 1) != 0) {
  atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "mbedtls_md_setup failed\n");
  return 1;
  }

  if (mbedtls_md_starts(&md_ctx) != 0) {
  atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "mbedtls_md_starts failed\n");
  return 1;
  }

  if (mbedtls_md_update(&md_ctx, message, message_len) != 0) {
  atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "mbedtls_md_update failed\n");
  return 1;
  }

  unsigned char hash[MBEDTLS_MD_MAX_SIZE];
  if (mbedtls_md_finish(&md_ctx, hash) != 0) {
  atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "mbedtls_md_finish failed\n");
  return 1;
  }

  /*
   * 3. Generate key pair
   */
  unsigned char seed[32];
  if (atchops_platform_random(seed, sizeof(seed)) != 0) {
  atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "Failed to generate random seed\n");
  return 1;
  }

  unsigned char private_key_generated[32];
  if (mbedtls_md(md_info, seed, sizeof(seed), private_key_generated) != 0) {
  atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "mbedtls_md failed for private key generation\n");
  return 1;
  }

  unsigned char public_key_generated[32];
  atchops_ed25519_scalar_mult_base(public_key_generated, private_key_generated);

  atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_DEBUG, "Key pair generated successfully\n");

  /*
   * 4. Hash private key
   */
  size_t private_key_hash_size = 32;
  unsigned char private_key_hash[MBEDTLS_MD_MAX_SIZE];

  if (mbedtls_md(md_info, private_key_generated, sizeof(private_key_generated), private_key_hash) != 0) {
  atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "mbedtls_md failed\n");
  return 1;
  }

  
  /*
   * 4.5. Verify the signature with the public key
   */
  if (mbedtls_ecdsa_verify(&md_ctx, hash, sizeof(hash), public_key_generated, signature, 64) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "Signature verification failed\n");
    return 1;
  }

  atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_DEBUG, "Signature verified successfully\n");
  /*
   * 5. Compute r
   */
  unsigned char r[MBEDTLS_MD_MAX_SIZE];
  unsigned char concatenated[MBEDTLS_MD_MAX_SIZE + message_len];
  memcpy(concatenated, private_key_hash + private_key_hash_size / 2, private_key_hash_size / 2);
  memcpy(concatenated + private_key_hash_size / 2, message, message_len);

  if (mbedtls_md(md_info, concatenated, private_key_hash_size / 2 + message_len, r) != 0) {
  atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "mbedtls_md failed for r\n");
  return 1;
  }

  /*
   * 6. Perform r modulo L
   */
  unsigned char r_mod_l[32];
  atchops_ed25519_mod_l(r_mod_l, r);

  unsigned char R[32];
  atchops_ed25519_scalar_mult_base(R, r_mod_l);

  unsigned char encoded_R[32];
  atchops_ed25519_encode_point(encoded_R, R);
  memcpy(signature, encoded_R, 32);

  /*
   * 7. Compute H(R, A, M)
   */
  unsigned char h_ram[MBEDTLS_MD_MAX_SIZE];
  unsigned char ram_concat[64 + message_len];
  memcpy(ram_concat, encoded_R, 32);
  memcpy(ram_concat + 32, public_key_generated, 32);
  memcpy(ram_concat + 64, message, message_len);

  if (mbedtls_md(md_info, ram_concat, 64 + message_len, h_ram) != 0) {
  atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "mbedtls_md failed for H(R, A, M)\n");
  return 1;
  }

  /*
   * 8. Compute s = (r + H(R, A, M) * a) mod L
   */
  unsigned char h_ram_mod_l[32];
  atchops_ed25519_mod_l(h_ram_mod_l, h_ram);

  unsigned char s[32];
  atchops_ed25519_scalar_mult_add(s, r_mod_l, h_ram_mod_l, private_key_hash);

  memcpy(signature + 32, s, 32);

  /*
   * 9. Cleanup
   */
  mbedtls_md_free(&md_ctx);

  return 0;
}
