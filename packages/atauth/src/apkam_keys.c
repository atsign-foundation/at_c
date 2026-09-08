#include "apkam_keys.h"
#include "atchops/aes.h"
#include "atchops/base64.h"
#include "atchops/rsa_key.h"
#include "atclient/atkeys.h"
#include "atlogger/atlogger.h"
#include <mbedtls/platform_util.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define TAG "atauth_apkam"

// Scrub key material before releasing it: freed heap pages holding raw keys
// can otherwise surface in core dumps or later allocations.
// mbedtls_platform_zeroize is guaranteed not to be optimized away.
static void zero_free(void *ptr, size_t len) {
  if (ptr != NULL) {
    mbedtls_platform_zeroize(ptr, len);
    free(ptr);
  }
}

static void zero_free_str(char *str) {
  if (str != NULL) {
    zero_free(str, strlen(str));
  }
}

// SYMMETRIC KEY

void atauth_apkam_symmetric_key_init(struct atauth_apkam_symmetric_key *key) {
  key->symmetric_key_raw = NULL;
  key->symmetric_key_base64 = NULL;
  key->encrypted_symmetric_key_base64 = NULL;
  key->symmetric_key_raw_len = 0;
  key->symmetric_key_base64_len = 0;
  key->encrypted_symmetric_key_base64_len = 0;
}

int atauth_apkam_symmetric_key_generate(struct atauth_apkam_symmetric_key *key,
                                        const atchops_rsa_key_public_key *default_encryption_public_key) {
  int ret;
  size_t cipher_text_len = 256; // size for rsa 2048 encrypt
  unsigned char cipher_text[cipher_text_len];

  key->symmetric_key_raw_len = ATCHOPS_AES_256 / 8;
  key->symmetric_key_raw = malloc(sizeof(unsigned char) * (key->symmetric_key_raw_len));
  // NULL checked by function
  ret = atchops_aes_generate_key(key->symmetric_key_raw, ATCHOPS_AES_256);
  if (ret != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "Failed to generate symmetric key\n");
    goto exit;
  }

  key->symmetric_key_base64_len = atchops_base64_encoded_size(key->symmetric_key_raw_len);
  key->symmetric_key_base64 = malloc(sizeof(char) * (key->symmetric_key_base64_len + 1));
  // NULL checked by function
  ret = atchops_base64_encode(key->symmetric_key_raw, key->symmetric_key_raw_len, key->symmetric_key_base64,
                              key->symmetric_key_base64_len, &key->symmetric_key_base64_len);
  if (ret != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "Failed to base64 encode symmetric key iv\n");
    goto exit;
  }

  ret = atchops_rsa_encrypt(default_encryption_public_key, (unsigned char *)key->symmetric_key_base64,
                            key->symmetric_key_base64_len, cipher_text, cipher_text_len, &cipher_text_len);
  if (ret != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "Failed to encrypt symmetric key: %d\n", ret);
    goto exit;
  }

  // base64 encode encrypted symmetric key
  key->encrypted_symmetric_key_base64_len = atchops_base64_encoded_size(cipher_text_len);
  key->encrypted_symmetric_key_base64 = malloc(sizeof(char) * (key->encrypted_symmetric_key_base64_len + 1));
  // NULL checked by function
  ret = atchops_base64_encode(cipher_text, cipher_text_len, key->encrypted_symmetric_key_base64,
                              key->encrypted_symmetric_key_base64_len, &key->encrypted_symmetric_key_base64_len);
  if (ret != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "Failed to base64 encode symmetric key iv\n");
    goto exit;
  }
  key->symmetric_key_base64[key->symmetric_key_base64_len] = 0;
  memset(cipher_text, 0, cipher_text_len);

exit:
  if (ret != 0) {
    atauth_apkam_symmetric_key_free(key);
  }
  return ret;
}

void atauth_apkam_symmetric_key_free(struct atauth_apkam_symmetric_key *key) {
  zero_free(key->symmetric_key_raw, key->symmetric_key_raw_len);
  zero_free_str(key->symmetric_key_base64);
  free(key->encrypted_symmetric_key_base64); // ciphertext, no need to scrub
  atauth_apkam_symmetric_key_init(key);
}

// FIRST ENROLLMENT

void atauth_generated_first_enrollment_keys_init(struct atauth_generated_first_enrollment_keys *keys) {
  keys->apkam_public_key = NULL;
  keys->apkam_private_key = NULL;
  keys->encrypt_public_key = NULL;
  keys->encrypt_private_key = NULL;
  keys->self_encryption_key_raw = NULL;
  keys->self_encryption_key_raw_len = 0;
  keys->self_encryption_key_base64 = NULL;
  keys->self_encryption_key_base64_len = 0;
}

int atauth_generated_first_enrollment_keys_generate(struct atauth_generated_first_enrollment_keys *keys) {
  int ret;
  ret = atchops_rsa_key_generate_base64(&keys->apkam_public_key, &keys->apkam_private_key);
  if (ret != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "Failed to generate apkam key pair\n");
    goto exit;
  }
  ret = atchops_rsa_key_generate_base64(&keys->encrypt_public_key, &keys->encrypt_private_key);
  if (ret != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "Failed to generate default encryption key pair\n");
    goto exit;
  }
  keys->self_encryption_key_raw_len = ATCHOPS_AES_256 / 8; // bits to bytes
  keys->self_encryption_key_raw = malloc(sizeof(unsigned char) * (keys->self_encryption_key_raw_len));
  // function already has a built in check for NULL
  ret = atchops_aes_generate_key(keys->self_encryption_key_raw, ATCHOPS_AES_256);
  if (ret != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "Failed to generate self encryption key pair\n");
    goto exit;
  }
  keys->self_encryption_key_base64_len = atchops_base64_encoded_size(keys->self_encryption_key_raw_len);
  keys->self_encryption_key_base64 = malloc(sizeof(char) * keys->self_encryption_key_base64_len);
  // function already has a built in check for NULL
  ret = atchops_base64_encode(keys->self_encryption_key_raw, keys->self_encryption_key_raw_len,
                              keys->self_encryption_key_base64, keys->self_encryption_key_base64_len,
                              &keys->self_encryption_key_base64_len);
  if (ret != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "Failed to base64 encode self encryption key pair\n");
    goto exit;
  }
exit:
  if (ret != 0) {
    atauth_generated_first_enrollment_keys_free(keys);
  }
  return ret;
}

int atauth_generated_first_enrollment_keys_populate_atkeys(
    const struct atauth_generated_first_enrollment_keys *generated_keys, atclient_atkeys *atkeys) {
  int ret;
  ret = atclient_atkeys_set_pkam_private_key_base64(atkeys, generated_keys->apkam_private_key,
                                                    strlen(generated_keys->apkam_private_key));
  if (ret != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "Failed to load atkeys with apkam private key\n");
    return ret;
  }
  ret = atclient_atkeys_set_pkam_public_key_base64(atkeys, generated_keys->apkam_public_key,
                                                   strlen(generated_keys->apkam_public_key));
  if (ret != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "Failed to load atkeys with apkam public key\n");
    return ret;
  }
  ret = atclient_atkeys_set_encrypt_private_key_base64(atkeys, generated_keys->encrypt_private_key,
                                                       strlen(generated_keys->encrypt_private_key));
  if (ret != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "Failed to load atkeys with encrypt private key\n");
    return ret;
  }
  ret = atclient_atkeys_set_encrypt_public_key_base64(atkeys, generated_keys->encrypt_public_key,
                                                      strlen(generated_keys->encrypt_public_key));
  if (ret != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "Failed to load atkeys with encrypt public key\n");
    return ret;
  }
  ret = atclient_atkeys_populate_pkam_private_key(atkeys, generated_keys->apkam_private_key,
                                                  strlen(generated_keys->apkam_private_key));
  if (ret != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "Failed to populate atkeys with apkam private key\n");
    return ret;
  }
  ret = atclient_atkeys_populate_pkam_public_key(atkeys, generated_keys->apkam_public_key,
                                                 strlen(generated_keys->apkam_public_key));
  if (ret != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "Failed to populate atkeys with apkam public key\n");
    return ret;
  }
  ret = atclient_atkeys_populate_encrypt_private_key(atkeys, generated_keys->encrypt_private_key,
                                                     strlen(generated_keys->encrypt_private_key));
  if (ret != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "Failed to populate atkeys with encrypt private key\n");
    return ret;
  }
  ret = atclient_atkeys_populate_encrypt_public_key(atkeys, generated_keys->encrypt_public_key,
                                                    strlen(generated_keys->encrypt_public_key));
  if (ret != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "Failed to populate atkeys with encrypt public key\n");
    return ret;
  }
  ret = atclient_atkeys_set_self_encryption_key_base64(atkeys, generated_keys->self_encryption_key_base64,
                                                       generated_keys->self_encryption_key_base64_len);
  if (ret != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "Failed to populate atkeys with self encryption key\n");
    return ret;
  }

  return 0;
}

void atauth_generated_first_enrollment_keys_free(struct atauth_generated_first_enrollment_keys *keys) {
  free(keys->apkam_public_key);
  zero_free_str(keys->apkam_private_key);
  free(keys->encrypt_public_key);
  zero_free_str(keys->encrypt_private_key);
  zero_free(keys->self_encryption_key_raw, keys->self_encryption_key_raw_len);
  if (keys->self_encryption_key_base64 != NULL) {
    zero_free(keys->self_encryption_key_base64, keys->self_encryption_key_base64_len);
  }
  atauth_generated_first_enrollment_keys_init(keys);
}

// APKAM ENROLLMENT

void atauth_generated_apkam_enrollment_keys_init(struct atauth_generated_apkam_enrollment_keys *keys) {
  keys->apkam_public_key = NULL;
  keys->apkam_private_key = NULL;
  atauth_apkam_symmetric_key_init(&keys->apkam_symmetric_key);
}
int atauth_generated_apkam_enrollment_keys_generate(struct atauth_generated_apkam_enrollment_keys *keys,
                                                    const atchops_rsa_key_public_key *default_encryption_public_key) {
  int ret;

  ret = atchops_rsa_key_generate_base64(&keys->apkam_public_key, &keys->apkam_private_key);
  if (ret != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "Failed to generate apkam key pair\n");
    goto exit;
  }
  ret = atauth_apkam_symmetric_key_generate(&keys->apkam_symmetric_key, default_encryption_public_key);
  if (ret != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "Failed to generate & encrypt apkam symmetric key\n");
    goto exit;
  }
exit:
  if (ret != 0) {
    atauth_generated_apkam_enrollment_keys_free(keys);
  }
  return ret;
}

int atauth_generated_apkam_enrollment_keys_populate_atkeys(
    const struct atauth_generated_apkam_enrollment_keys *generated_keys, atclient_atkeys *atkeys) {
  int ret;
  ret = atclient_atkeys_set_pkam_private_key_base64(atkeys, generated_keys->apkam_private_key,
                                                    strlen(generated_keys->apkam_private_key));
  if (ret != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "Failed to load atkeys with apkam private key\n");
    return ret;
  }
  ret = atclient_atkeys_set_pkam_public_key_base64(atkeys, generated_keys->apkam_public_key,
                                                   strlen(generated_keys->apkam_public_key));
  if (ret != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "Failed to load atkeys with apkam public key\n");
    return ret;
  }
  ret = atclient_atkeys_populate_pkam_private_key(atkeys, generated_keys->apkam_private_key,
                                                  strlen(generated_keys->apkam_private_key));
  if (ret != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "Failed to populate atkeys with apkam private key\n");
    return ret;
  }
  ret = atclient_atkeys_populate_pkam_public_key(atkeys, generated_keys->apkam_public_key,
                                                 strlen(generated_keys->apkam_public_key));
  if (ret != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "Failed to populate atkeys with apkam public key\n");
    return ret;
  }
  ret = atclient_atkeys_set_apkam_symmetric_key_base64(atkeys, generated_keys->apkam_symmetric_key.symmetric_key_base64,
                                                       generated_keys->apkam_symmetric_key.symmetric_key_base64_len);
  if (ret != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "Failed to populate atkeys with apkam symmetric key\n");
    return ret;
  }

  return 0;
}

void atauth_generated_apkam_enrollment_keys_free(struct atauth_generated_apkam_enrollment_keys *keys) {
  free(keys->apkam_public_key);
  keys->apkam_public_key = NULL;
  zero_free_str(keys->apkam_private_key);
  keys->apkam_private_key = NULL;
  atauth_apkam_symmetric_key_free(&keys->apkam_symmetric_key);
}
