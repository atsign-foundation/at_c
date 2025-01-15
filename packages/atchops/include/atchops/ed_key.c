#include "atchops/ed_key.h"
#include "atchops/base64.h"
#include "atchops/constants.h"
#include "atchops/mbedtls.h"
#include <atchops/platform.h>
#include <atlogger/atlogger.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <mbedtls/entropy.h>
#include <mbedtls/ctr_drbg.h>

#define TAG "ed_key"

static mbedtls_entropy_context entropy;
static mbedtls_ctr_drbg_context ctr_drbg;
static int rng_initialized = 0;

static int initialize_rng() {
  const char *pers = "ed25519_key_rng";

  if (rng_initialized) {
    return 0; // Already initialized
  }

  mbedtls_entropy_init(&entropy);
  mbedtls_ctr_drbg_init(&ctr_drbg);

  int ret = mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func, &entropy, (const unsigned char *)pers, strlen(pers));
  if (ret != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "Failed to seed RNG: %d\n", ret);
    mbedtls_entropy_free(&entropy);
    mbedtls_ctr_drbg_free(&ctr_drbg);
    return 1;
  }

  rng_initialized = 1;
  return 0;
}

void atchops_ed_key_public_key_init(atchops_ed_key_public_key *public_key) {
  if (public_key == NULL) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "public_key is null\n");
    return;
  }
  memset(public_key, 0, sizeof(atchops_ed_key_public_key));
}

void atchops_ed_key_public_key_free(atchops_ed_key_public_key *public_key) {
  if (public_key == NULL) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "public_key is null\n");
    return;
  }
  if (atchops_ed_key_public_key_is_key_initialized(public_key)) {
    atchops_ed_key_public_key_unset_key(public_key);
  }
  memset(public_key, 0, sizeof(atchops_ed_key_public_key));
}

void atchops_ed_key_private_key_init(atchops_ed_key_private_key *private_key) {
  if (private_key == NULL) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "private_key is null\n");
    return;
  }
  memset(private_key, 0, sizeof(atchops_ed_key_private_key));
}

void atchops_ed_key_private_key_free(atchops_ed_key_private_key *private_key) {
  if (private_key == NULL) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "private_key is null\n");
    return;
  }
  if (atchops_ed_key_private_key_is_key_initialized(private_key)) {
    atchops_ed_key_private_key_unset_key(private_key);
  }
  if (atchops_ed_key_private_key_is_seed_initialized(private_key)) {
    atchops_ed_key_private_key_unset_seed(private_key);
  }
  memset(private_key, 0, sizeof(atchops_ed_key_private_key));
}

int atchops_ed_key_public_key_clone(const atchops_ed_key_public_key *src, atchops_ed_key_public_key *dst) {
  if (src == NULL || dst == NULL) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "src or dst is null\n");
    return 1;
  }
  if (atchops_ed_key_public_key_set_key(dst, src->key, src->key_len) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "Failed to set public key\n");
    return 1;
  }
  return 0;
}

int atchops_ed_key_private_key_clone(const atchops_ed_key_private_key *src, atchops_ed_key_private_key *dst) {
  if (src == NULL || dst == NULL) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "src or dst is null\n");
    return 1;
  }
  if (atchops_ed_key_private_key_set_key(dst, src->key, src->key_len) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "Failed to set private key\n");
    return 1;
  }
  if (atchops_ed_key_private_key_set_seed(dst, src->seed, src->seed_len) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "Failed to set private key seed\n");
    return 1;
  }
  return 0;
}

// Additional cleanup function to release RNG resources
void cleanup_rng() {
  if (rng_initialized) {
    mbedtls_ctr_drbg_free(&ctr_drbg);
    mbedtls_entropy_free(&entropy);
    rng_initialized = 0;
  }
}

