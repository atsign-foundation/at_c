#include "apkam_keys.h"
#include "atchops/aes.h"
#include "atchops/aes_ctr.h"
#include "atchops/base64.h"
#include "atchops/iv.h"
#include "atchops/rsa_key.h"
#include "atclient/atkeys.h"
#include "atlogger/atlogger.h"
#include <stdlib.h>
#include <string.h>

#define TAG "atauth_apkam"

void atauth_apkam_keys_init(struct atauth_apkam_keys *keys) {
  keys->apkam_symmetric_key_bytes = NULL;
  keys->apkam_symmetric_key_base64 = NULL;
  keys->pkam_public_key_base64 = NULL;
  keys->pkam_private_key_base64 = NULL;
  keys->encrypt_public_key_base64 = NULL;
  keys->encrypt_private_key_base64 = NULL;
  keys->self_encryption_key_bytes = NULL;
  keys->self_encryption_key_base64 = NULL;
  keys->encrypted_encrypt_private_key_base64 = NULL;
  keys->encrypted_encrypt_private_iv_base64 = NULL;
  keys->encrypted_self_encryption_key_base64 = NULL;
  keys->encrypted_self_encryption_key_iv_base64 = NULL;
}

void atauth_apkam_keys_free(struct atauth_apkam_keys *keys) {
  if (keys->apkam_symmetric_key_bytes != NULL) {
    free(keys->apkam_symmetric_key_bytes);
    keys->apkam_symmetric_key_bytes = NULL;
  }
  if (keys->apkam_symmetric_key_base64 != NULL) {
    free(keys->apkam_symmetric_key_base64);
    keys->apkam_symmetric_key_base64 = NULL;
  }
  if (keys->pkam_public_key_base64 != NULL) {
    free(keys->pkam_public_key_base64);
    keys->pkam_public_key_base64 = NULL;
  }
  if (keys->pkam_private_key_base64 != NULL) {
    free(keys->pkam_private_key_base64);
    keys->pkam_private_key_base64 = NULL;
  }
  if (keys->encrypt_public_key_base64 != NULL) {
    free(keys->encrypt_public_key_base64);
    keys->encrypt_public_key_base64 = NULL;
  }
  if (keys->encrypt_private_key_base64 != NULL) {
    free(keys->encrypt_private_key_base64);
    keys->encrypt_private_key_base64 = NULL;
  }
  if (keys->self_encryption_key_bytes != NULL) {
    free(keys->self_encryption_key_bytes);
    keys->self_encryption_key_bytes = NULL;
  }
  if (keys->self_encryption_key_base64 != NULL) {
    free(keys->self_encryption_key_base64);
    keys->self_encryption_key_base64 = NULL;
  }
  if (keys->encrypted_encrypt_private_key_base64 != NULL) {
    free(keys->encrypted_encrypt_private_key_base64);
    keys->encrypted_encrypt_private_key_base64 = NULL;
  }
  if (keys->encrypted_encrypt_private_iv_base64 != NULL) {
    free(keys->encrypted_encrypt_private_iv_base64);
    keys->encrypted_encrypt_private_iv_base64 = NULL;
  }
  if (keys->encrypted_self_encryption_key_base64 != NULL) {
    free(keys->encrypted_self_encryption_key_base64);
    keys->encrypted_self_encryption_key_base64 = NULL;
  }
  if (keys->encrypted_self_encryption_key_iv_base64 != NULL) {
    free(keys->encrypted_self_encryption_key_iv_base64);
    keys->encrypted_self_encryption_key_iv_base64 = NULL;
  }
}

int atauth_apkam_keys_generate_all(struct atauth_apkam_keys *keys) {
  int ret = 0;

  const size_t AES256_SIZE = 32; // in bytes
  size_t AES256_B64_SIZE = atchops_base64_encoded_size(AES256_SIZE);
  const size_t RSA2048_SIZE = 256; // in bytes
  size_t RSA2048_B64_SIZE = atchops_base64_encoded_size(RSA2048_SIZE);

  // Generate APKAM Symmetric Key

  keys->apkam_symmetric_key_bytes = malloc(AES256_SIZE);
  if (ret != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "Failed to allocate APKAM symmetric key\n");
    goto exit;
  }

  ret = atchops_aes_generate_key(keys->apkam_symmetric_key_bytes, ATCHOPS_AES_256);
  if (ret != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "Failed to generate APKAM symmetric key\n");
    goto exit;
  }

  // base64 encoded APKAM symmetric key

  keys->apkam_symmetric_key_base64 = malloc(sizeof(char) * (AES256_B64_SIZE + 1));
  if (ret != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "Failed to allocate APKAM symmetric key base64\n");
    goto exit;
  }

  size_t apkam_symmetric_key_base64_len;
  ret = atchops_base64_encode(keys->apkam_symmetric_key_bytes, AES256_SIZE, keys->apkam_symmetric_key_base64,
                              AES256_B64_SIZE, &apkam_symmetric_key_base64_len);
  if (ret != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "Failed to base64 encode APKAM symmetric key\n");
    goto exit;
  }
  keys->apkam_symmetric_key_base64[apkam_symmetric_key_base64_len] = 0;

  // generate pkam keys
  ret = atchops_rsa_key_generate_base64(&keys->pkam_public_key_base64, &keys->pkam_private_key_base64);
  if (ret != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "Failed to generate PKAM key pair\n");
    goto exit;
  }

  // generate encrypt keys
  ret = atchops_rsa_key_generate_base64(&keys->encrypt_public_key_base64, &keys->encrypt_private_key_base64);
  if (ret != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "Failed to generate encrypt key pair\n");
    goto exit;
  }

  // generate self encryption key
  keys->self_encryption_key_bytes = malloc(AES256_SIZE);
  if (ret != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "Failed to allocate self encryption key\n");
    goto exit;
  }

  ret = atchops_aes_generate_key(keys->self_encryption_key_bytes, ATCHOPS_AES_256);
  if (ret != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "Failed to generate self encryption key\n");
    goto exit;
  }

  // base64 encoded self encryption key

  keys->self_encryption_key_base64 = malloc(sizeof(char) * (AES256_B64_SIZE + 1));
  if (ret != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "Failed to allocate self encryption key base64\n");
    goto exit;
  }

  size_t self_encryption_key_base64_len;
  ret = atchops_base64_encode(keys->self_encryption_key_bytes, AES256_SIZE, keys->self_encryption_key_base64,
                              AES256_B64_SIZE, &self_encryption_key_base64_len);
  if (ret != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "Failed to base64 encode self encryption key\n");
    goto exit;
  }
  keys->self_encryption_key_base64[self_encryption_key_base64_len] = 0;

  // generate encrypt private iv
  unsigned char encrypt_private_iv[ATCHOPS_IV_BUFFER_SIZE];
  ret = atchops_iv_generate(encrypt_private_iv);
  if (ret != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "Failed to generate encrypt private key iv\n");
    goto exit;
  }

  // base64 encode encrypt private iv
  size_t encrypt_private_iv_base64_len = atchops_base64_encoded_size(ATCHOPS_IV_BUFFER_SIZE);
  keys->encrypted_encrypt_private_iv_base64 = malloc(sizeof(char) * (encrypt_private_iv_base64_len + 1));
  if (keys->encrypted_encrypt_private_iv_base64 == NULL) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR,
                 "Failed to allocate base64 encoded, encrypted encrypt private iv\n");
    ret = 1;
    goto exit;
  }

  size_t encrypt_private_iv_base64_olen;
  ret = atchops_base64_encode(encrypt_private_iv, ATCHOPS_IV_BUFFER_SIZE, keys->encrypted_encrypt_private_iv_base64,
                              encrypt_private_iv_base64_len, &encrypt_private_iv_base64_olen);
  if (ret != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "Failed to base64 encode encrypted encrypt private iv\n");
    goto exit;
  }
  if (encrypt_private_iv_base64_olen > encrypt_private_iv_base64_len) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR,
                 "Failed to base64 encode encrypted encrypt private iv: output exceeds allocated length\n");
  }
  keys->encrypted_encrypt_private_iv_base64[encrypt_private_iv_base64_len] = 0;

  // encrypt encrypt private key
  size_t encrypt_private_key_base64_cipher_len = atchops_aes_ctr_ciphertext_size(RSA2048_B64_SIZE);
  unsigned char *encrypt_private_key_base64_cipher = malloc(encrypt_private_key_base64_cipher_len);

  if (encrypt_private_key_base64_cipher == NULL) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "Failed to allocate encrypt private key ciphertext\n");
    goto exit;
  }

  size_t encrypt_private_key_base64_cipher_olen;
  ret = atchops_aes_ctr_encrypt(keys->apkam_symmetric_key_bytes, ATCHOPS_AES_256, encrypt_private_iv,
                                (unsigned char *)keys->encrypt_private_key_base64, RSA2048_B64_SIZE,
                                encrypt_private_key_base64_cipher, encrypt_private_key_base64_cipher_len,
                                &encrypt_private_key_base64_cipher_olen);
  if (ret != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "Failed to encrypt encrypt private key\n");
    free(encrypt_private_key_base64_cipher);
    goto exit;
  }

  // base64 encode encrypted encrypt private key

  size_t encrypted_encrypt_private_key_base64_len = atchops_base64_encoded_size(encrypt_private_key_base64_cipher_olen);
  keys->encrypted_encrypt_private_key_base64 = malloc(encrypted_encrypt_private_key_base64_len);
  if (keys->encrypted_encrypt_private_key_base64 == NULL) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR,
                 "Failed to allocate base64 encoded, encrypted encrypt private key\n");
    free(encrypt_private_key_base64_cipher);
    goto exit;
  }

  ret = atchops_base64_encode(encrypt_private_key_base64_cipher, encrypt_private_key_base64_cipher_olen,
                              keys->encrypted_encrypt_private_key_base64, encrypted_encrypt_private_key_base64_len,
                              &keys->encrypted_encrypt_private_key_base64_len);
  free(encrypt_private_key_base64_cipher);

  // generate self encryption iv
  unsigned char self_encrypt_iv[ATCHOPS_IV_BUFFER_SIZE];
  ret = atchops_iv_generate(self_encrypt_iv);
  if (ret != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "Failed to generate self encryption key iv\n");
    goto exit;
  }

  // encrypt self encryption key

  size_t self_encryption_key_base64_cipher_len = atchops_aes_ctr_ciphertext_size(AES256_B64_SIZE);
  unsigned char *self_encryption_key_base64_cipher = malloc(self_encryption_key_base64_cipher_len);

  if (self_encryption_key_base64_cipher == NULL) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "Failed to allocate self encryption key ciphertext\n");
    goto exit;
  }

  size_t self_encryption_key_base64_cipher_olen;
  ret = atchops_aes_ctr_encrypt(keys->apkam_symmetric_key_bytes, ATCHOPS_AES_256, self_encrypt_iv,
                                (unsigned char *)keys->self_encryption_key_base64, AES256_B64_SIZE,
                                self_encryption_key_base64_cipher, self_encryption_key_base64_cipher_len,
                                &self_encryption_key_base64_cipher_olen);
  if (ret != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "Failed to encrypt self encryption key\n");
    free(self_encryption_key_base64_cipher);
    goto exit;
  }

  // base64 encode encrypted self encryption key

  size_t encrypted_self_encryption_key_base64_len = atchops_base64_encoded_size(self_encryption_key_base64_cipher_olen);
  keys->encrypted_self_encryption_key_base64 = malloc(encrypted_self_encryption_key_base64_len);
  if (keys->encrypted_self_encryption_key_base64 == NULL) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR,
                 "Failed to allocate base64 encoded, encrypted self encryption key\n");
    free(self_encryption_key_base64_cipher);
    goto exit;
  }

  ret = atchops_base64_encode(self_encryption_key_base64_cipher, self_encryption_key_base64_cipher_olen,
                              keys->encrypted_self_encryption_key_base64, encrypted_self_encryption_key_base64_len,
                              &keys->encrypted_self_encryption_key_base64_len);
  free(self_encryption_key_base64_cipher);

  goto success;
exit:
  atauth_apkam_keys_free(keys);
success:
  return ret;
}

int atauth_apkam_keys_create_atkeys(const struct atauth_apkam_keys *keys, atclient_atkeys **atkeys_out) {
  if (atkeys_out == NULL) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atkeys_out parameter is and cannot be NULL\n");
    return 1;
  }

  atclient_atkeys *atkeys = malloc(sizeof(atclient_atkeys));
  if (atkeys == NULL) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "Failed to allocate atclient_atkeys\n");
    return 1;
  }

  int ret;
  // set the base64 values and populate the raw rsa numbers
  ret = atclient_atkeys_set_pkam_public_key_base64(atkeys, (char *)keys->pkam_public_key_base64,
                                                   strlen((char *)keys->pkam_public_key_base64));
  if (ret != 0) {
    return ret;
  }
  ret = atclient_atkeys_populate_pkam_public_key(atkeys, (char *)keys->pkam_public_key_base64,
                                                 strlen((char *)keys->pkam_public_key_base64));
  if (ret != 0) {
    return ret;
  }
  ret = atclient_atkeys_set_pkam_private_key_base64(atkeys, (char *)keys->pkam_private_key_base64,
                                                    strlen((char *)keys->pkam_private_key_base64));
  if (ret != 0) {
    return ret;
  }
  ret = atclient_atkeys_populate_pkam_private_key(atkeys, (char *)keys->pkam_private_key_base64,
                                                  strlen((char *)keys->pkam_private_key_base64));
  if (ret != 0) {
    return ret;
  }
  ret = atclient_atkeys_set_encrypt_public_key_base64(atkeys, (char *)keys->pkam_public_key_base64,
                                                      strlen((char *)keys->encrypt_public_key_base64));
  if (ret != 0) {
    return ret;
  }
  ret = atclient_atkeys_populate_encrypt_public_key(atkeys, (char *)keys->pkam_public_key_base64,
                                                    strlen((char *)keys->encrypt_public_key_base64));
  if (ret != 0) {
    return ret;
  }
  ret = atclient_atkeys_set_encrypt_private_key_base64(atkeys, (char *)keys->pkam_private_key_base64,
                                                       strlen((char *)keys->encrypt_private_key_base64));
  if (ret != 0) {
    return ret;
  }
  ret = atclient_atkeys_populate_encrypt_private_key(atkeys, (char *)keys->pkam_private_key_base64,
                                                     strlen((char *)keys->encrypt_private_key_base64));
  if (ret != 0) {
    return ret;
  }
  ret = atclient_atkeys_set_apkam_symmetric_key_base64(atkeys, keys->apkam_symmetric_key_base64,
                                                       strlen((char *)keys->apkam_symmetric_key_base64));
  if (ret != 0) {
    return ret;
  }
  ret = atclient_atkeys_set_self_encryption_key_base64(atkeys, keys->self_encryption_key_base64,
                                                       strlen((char *)keys->self_encryption_key_base64));
  if (ret != 0) {
    return ret;
  }

  *atkeys_out = atkeys;
  return 0;
}
