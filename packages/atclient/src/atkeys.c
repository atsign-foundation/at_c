#include "atclient/atkeys.h"
#include "atlogger/atlogger.h"
#include <atchops/aes_ctr.h>
#include <atchops/base64.h>
#include <atchops/iv.h>
#include <atchops/rsa.h>
#include <atchops/rsa_key.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>

#define TAG "atkeys"

static bool is_pkam_public_key_base64_initialized(atclient_atkeys *atkeys);
static bool is_pkam_private_key_base64_initialized(atclient_atkeys *atkeys);
static bool is_encrypt_public_key_base64_initialized(atclient_atkeys *atkeys);
static bool is_encrypt_private_key_base64_initialized(atclient_atkeys *atkeys);
static bool is_self_encryption_key_base64_initialized(atclient_atkeys *atkeys);
static bool is_enrollment_id_initialized(atclient_atkeys *atkeys);

static void set_pkam_public_key_base64_initialized(atclient_atkeys *atkeys, const bool initialized);
static void set_pkam_private_key_base64_initialized(atclient_atkeys *atkeys, const bool initialized);
static void set_encrypt_public_key_base64_initialized(atclient_atkeys *atkeys, const bool initialized);
static void set_encrypt_privatekey_base64_initialized(atclient_atkeys *atkeys, const bool initialized);
static void set_self_encryption_key_base64_initialized(atclient_atkeys *atkeys, const bool initialized);
static void set_enrollment_id_initialized(atclient_atkeys *atkeys, const bool initialized);

static void unset_pkam_public_key_base64(atclient_atkeys *atkeys);
static void unset_pkam_private_key_base64(atclient_atkeys *atkeys);
static void unset_encrypt_public_key_base64(atclient_atkeys *atkeys);
static void unset_encrypt_private_key_base64(atclient_atkeys *atkeys);
static void unset_self_encryption_key_base64(atclient_atkeys *atkeys);
static void unset_enrollment_id(atclient_atkeys *atkeys);

static int set_pkam_public_key_base64(atclient_atkeys *atkeys, const char *pkam_public_key_base64,
                                      const size_t pkam_public_key_len);
static int set_pkam_private_key_base64(atclient_atkeys *atkeys, const char *pkam_private_key_base64,
                                       const size_t pkam_private_key_len);
static int set_encrypt_public_key_base64(atclient_atkeys *atkeys, const char *encrypt_public_key_base64,
                                         const size_t encrypt_public_key_len);
static int set_encrypt_private_key_base64(atclient_atkeys *atkeys, const char *encrypt_private_key_base64,
                                          const size_t encrypt_private_key_len);
static int set_self_encryption_key_base64(atclient_atkeys *atkeys, const char *self_encryption_key_base64,
                                          const size_t self_encryption_key_len);
static int set_enrollment_id(atclient_atkeys *atkeys, const char *enrollment_id, const size_t enrollment_id_len);

void atclient_atkeys_init(atclient_atkeys *atkeys) {
  memset(atkeys, 0, sizeof(atclient_atkeys));
  atchops_rsa_key_public_key_init(&(atkeys->pkam_public_key));
  atchops_rsa_key_private_key_init(&(atkeys->pkam_private_key));
  atchops_rsa_key_public_key_init(&(atkeys->encrypt_public_key));
  atchops_rsa_key_private_key_init(&(atkeys->encrypt_private_key));
  atkeys->pkam_public_key_base64 = NULL;
  atkeys->pkam_private_key_base64 = NULL;
  atkeys->encrypt_public_key_base64 = NULL;
  atkeys->encrypt_private_key_base64 = NULL;
  atkeys->self_encryption_key_base64 = NULL;
  atkeys->enrollment_id = NULL;
}

void atclient_atkeys_free(atclient_atkeys *atkeys) {
  if (atkeys == NULL) {
    return;
  }

  atchops_rsa_key_public_key_free(&(atkeys->pkam_public_key));
  atchops_rsa_key_private_key_free(&(atkeys->pkam_private_key));
  atchops_rsa_key_public_key_free(&(atkeys->encrypt_public_key));
  atchops_rsa_key_private_key_free(&(atkeys->encrypt_private_key));
  if (atclient_atkeys_is_pkam_public_key_base64_initialized(atkeys)) {
    unset_pkam_public_key_base64(atkeys);
  }
  if (atclient_atkeys_is_pkam_private_key_base64_initialized(atkeys)) {
    unset_pkam_private_key_base64(atkeys);
  }
  if (atclient_atkeys_is_encrypt_public_key_base64_initialized(atkeys)) {
    unset_encrypt_public_key_base64(atkeys);
  }
  if (atclient_atkeys_is_encrypt_private_key_base64_initialized(atkeys)) {
    unset_encrypt_private_key_base64(atkeys);
  }
  if (atclient_atkeys_is_self_encryption_key_base64_initialized(atkeys)) {
    unset_self_encryption_key_base64(atkeys);
  }
  if (atclient_atkeys_is_enrollment_id_initialized(atkeys)) {
    unset_enrollment_id(atkeys);
  }
}

int atclient_atkeys_set_pkam_public_key_base64(atclient_atkeys *atkeys, const char *pkam_public_key_base64,
                                               const size_t pkam_public_key_base64_len) {
  int ret = 1;

  if (atkeys == NULL) {
    ret = 1;
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atkeys is NULL\n");
    return ret;
  }

  if (pkam_public_key_base64 == NULL) {
    ret = 1;
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "pkam_public_key_base64 is NULL\n");
    return ret;
  }

  if (pkam_public_key_base64_len == 0) {
    ret = 1;
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "pkam_public_key_base64_len is 0\n");
    return ret;
  }

  if ((ret = set_pkam_public_key_base64(atkeys, pkam_public_key_base64, pkam_public_key_base64_len)) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR,
                 "set_pkam_public_key_base64: %d | failed to set pkam_public_key_base64\n", ret);
    goto exit;
  }

  ret = 0;
  goto exit;
exit: { return ret; }
}

int atclient_atkeys_set_pkam_private_key_base64(atclient_atkeys *atkeys, const char *pkam_private_key_base64,
                                                const size_t pkam_private_key_base64_len) {
  int ret = 1;

  if (atkeys == NULL) {
    ret = 1;
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atkeys is NULL\n");
    return ret;
  }

  if (pkam_private_key_base64 == NULL) {
    ret = 1;
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "pkam_private_key_base64 is NULL\n");
    return ret;
  }

  if (pkam_private_key_base64_len == 0) {
    ret = 1;
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "pkam_private_key_base64_len is 0\n");
    return ret;
  }

  if ((ret = set_pkam_private_key_base64(atkeys, pkam_private_key_base64, pkam_private_key_base64_len)) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR,
                 "set_pkam_private_key_base64: %d | failed to set pkam_private_key_base64\n", ret);
    goto exit;
  }

  ret = 0;
  goto exit;
exit: { return ret; }
}

int atclient_atkeys_set_encrypt_public_key_base64(atclient_atkeys *atkeys, const char *encrypt_public_key_base64,
                                                  const size_t encrypt_public_key_base64_len) {
  int ret = 1;

  if (atkeys == NULL) {
    ret = 1;
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atkeys is NULL\n");
    return ret;
  }

  if (encrypt_public_key_base64 == NULL) {
    ret = 1;
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "encrypt_public_key_base64 is NULL\n");
    return ret;
  }

  if (encrypt_public_key_base64_len == 0) {
    ret = 1;
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "encrypt_public_key_base64_len is 0\n");
    return ret;
  }

  if ((ret = set_encrypt_public_key_base64(atkeys, encrypt_public_key_base64, encrypt_public_key_base64_len)) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR,
                 "set_encrypt_public_key_base64: %d | failed to set encrypt_public_key_base64\n", ret);
    goto exit;
  }

  ret = 0;
  goto exit;
exit: { return ret; }
}

int atclient_atkeys_set_encrypt_private_key_base64(atclient_atkeys *atkeys, const char *encrypt_private_key_base64,
                                                   const size_t encrypt_private_key_base64_len) {
  int ret = 1;

  if (atkeys == NULL) {
    ret = 1;
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atkeys is NULL\n");
    return ret;
  }

  if (encrypt_private_key_base64 == NULL) {
    ret = 1;
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "encrypt_private_key_base64 is NULL\n");
    return ret;
  }

  if (encrypt_private_key_base64_len == 0) {
    ret = 1;
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "encrypt_private_key_base64_len is 0\n");
    return ret;
  }

  if ((ret = set_encrypt_private_key_base64(atkeys, encrypt_private_key_base64, encrypt_private_key_base64_len)) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR,
                 "set_encrypt_private_key_base64: %d | failed to set encrypt_private_key_base64\n", ret);
    goto exit;
  }

  ret = 0;
  goto exit;
exit: { return ret; }
}

int atclient_atkeys_set_self_encryption_key_base64(atclient_atkeys *atkeys, const char *self_encryption_key_base64,
                                                   const size_t self_encryption_key_base64_len) {
  int ret = 1;

  if (atkeys == NULL) {
    ret = 1;
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atkeys is NULL\n");
    return ret;
  }

  if (self_encryption_key_base64 == NULL) {
    ret = 1;
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "self_encryption_key_base64 is NULL\n");
    return ret;
  }

  if (self_encryption_key_base64_len == 0) {
    ret = 1;
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "self_encryption_key_base64_len is 0\n");
    return ret;
  }

  if ((ret = set_self_encryption_key_base64(atkeys, self_encryption_key_base64, self_encryption_key_base64_len)) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR,
                 "set_self_encryption_key_base64: %d | failed to set self_encryption_key_base64\n", ret);
    goto exit;
  }

  ret = 0;
  goto exit;
exit: { return ret; }
}

int atclient_atkeys_set_enrollment_id(atclient_atkeys *atkeys, const char *enrollment_id,
                                      const size_t enrollment_id_len) {
  int ret = 1;

  if (atkeys == NULL) {
    ret = 1;
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atkeys is NULL\n");
    return ret;
  }

  if (enrollment_id == NULL) {
    ret = 1;
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "enrollment_id is NULL\n");
    return ret;
  }

  if (enrollment_id_len == 0) {
    ret = 1;
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "enrollment_id_len is 0\n");
    return ret;
  }

  if (atclient_atkeys_is_enrollment_id_initialized(atkeys)) {
    unset_enrollment_id(atkeys);
  }

  if ((ret = set_enrollment_id(atkeys, enrollment_id, enrollment_id_len)) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "set_enrollment_id: %d | failed to set enrollment_id\n", ret);
    goto exit;
  }

  ret = 0;
  goto exit;
exit: { return ret; }
}

int atclient_atkeys_populate_pkam_public_key(atclient_atkeys *atkeys, const char *pkam_public_key_base64,
                                             const size_t pkam_public_key_base64_len) {
  int ret = 1;

  if (atkeys == NULL) {
    ret = 1;
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atkeys is NULL\n");
    return ret;
  }

  if (pkam_public_key_base64 == NULL) {
    ret = 1;
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "pkam_public_key_base64 is NULL\n");
    return ret;
  }

  if (pkam_public_key_base64_len == 0) {
    ret = 1;
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "pkam_public_key_base64_len is 0\n");
    return ret;
  }

  if ((ret = atchops_rsa_key_populate_public_key(&(atkeys->pkam_public_key), pkam_public_key_base64,
                                                 pkam_public_key_base64_len)) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR,
                 "atchops_rsa_key_populate_public_key: %d | failed to populate pkam_public_key\n", ret);
    goto exit;
  }
  ret = 0;
  goto exit;
exit: { return ret; }
}

int atclient_atkeys_populate_pkam_private_key(atclient_atkeys *atkeys, const char *pkam_private_key_base64,
                                              const size_t pkam_private_key_base64_len) {
  int ret = 1;

  if (atkeys == NULL) {
    ret = 1;
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atkeys is NULL\n");
    return ret;
  }

  if (pkam_private_key_base64 == NULL) {
    ret = 1;
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "pkam_private_key_base64 is NULL\n");
    return ret;
  }

  if (pkam_private_key_base64_len == 0) {
    ret = 1;
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "pkam_private_key_base64_len is 0\n");
    return ret;
  }

  if ((ret = atchops_rsa_key_populate_private_key(&(atkeys->pkam_private_key), pkam_private_key_base64,
                                                  pkam_private_key_base64_len)) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR,
                 "atchops_rsa_key_populate_private_key: %d | failed to populate pkam_private_key\n", ret);
    goto exit;
  }
exit: { return ret; }
}

int atclient_atkeys_populate_encrypt_public_key(atclient_atkeys *atkeys, const char *encrypt_public_key_base64,
                                                const size_t encrypt_public_key_base64_len) {
  int ret = 1;

  if (atkeys == NULL) {
    ret = 1;
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atkeys is NULL\n");
    return ret;
  }

  if (encrypt_public_key_base64 == NULL) {
    ret = 1;
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "encrypt_public_key_base64 is NULL\n");
    return ret;
  }

  if (encrypt_public_key_base64_len == 0) {
    ret = 1;
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "encrypt_public_key_base64_len is 0\n");
    return ret;
  }

  if ((ret = atchops_rsa_key_populate_public_key(&(atkeys->encrypt_public_key), encrypt_public_key_base64,
                                                 encrypt_public_key_base64_len)) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR,
                 "atchops_rsa_key_populate_public_key: %d | failed to populate encrypt_public_key\n", ret);
    goto exit;
  }

  ret = 0;
  goto exit;
exit: { return ret; }
}

int atclient_atkeys_populate_encrypt_private_key(atclient_atkeys *atkeys, const char *encrypt_private_key_base64,
                                                 const size_t encrypt_private_key_base64_len) {
  int ret = 1;

  if (atkeys == NULL) {
    ret = 1;
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atkeys is NULL\n");
    return ret;
  }

  if (encrypt_private_key_base64 == NULL) {
    ret = 1;
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "encrypt_private_key_base64 is NULL\n");
    return ret;
  }

  if (encrypt_private_key_base64_len == 0) {
    ret = 1;
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "encrypt_private_key_base64_len is 0\n");
    return ret;
  }

  if ((ret = atchops_rsa_key_populate_private_key(&(atkeys->encrypt_private_key), encrypt_private_key_base64,
                                                  encrypt_private_key_base64_len)) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR,
                 "atchops_rsa_key_populate_private_key: %d | failed to populate encrypt_private_key\n", ret);
    goto exit;
  }

  ret = 0;
  goto exit;
exit: { return ret; }
}

bool atclient_atkeys_is_pkam_public_key_base64_initialized(atclient_atkeys *atkeys) {
  return is_pkam_public_key_base64_initialized(atkeys);
}

bool atclient_atkeys_is_pkam_private_key_base64_initialized(atclient_atkeys *atkeys) {
  return is_pkam_private_key_base64_initialized(atkeys);
}

bool atclient_atkeys_is_encrypt_public_key_base64_initialized(atclient_atkeys *atkeys) {
  return is_encrypt_public_key_base64_initialized(atkeys);
}

bool atclient_atkeys_is_encrypt_private_key_base64_initialized(atclient_atkeys *atkeys) {
  return is_encrypt_private_key_base64_initialized(atkeys);
}

bool atclient_atkeys_is_self_encryption_key_base64_initialized(atclient_atkeys *atkeys) {
  return is_self_encryption_key_base64_initialized(atkeys);
}

bool atclient_atkeys_is_enrollment_id_initialized(atclient_atkeys *atkeys) {
  return is_enrollment_id_initialized(atkeys);
}

int atclient_atkeys_populate_from_strings(atclient_atkeys *atkeys, const char *aes_pkam_public_key_str,
                                          const size_t aes_pkam_public_key_len, const char *aes_pkam_private_key_str,
                                          const size_t aes_pkam_private_key_len, const char *aes_encrypt_public_key_str,
                                          const size_t aes_encrypt_public_key_len,
                                          const char *aes_encrypt_private_key_str,
                                          const size_t aes_encrypt_private_key_len, const char *self_encryption_key_str,
                                          const size_t self_encryption_key_str_len) {
  int ret = 1;

  /*
   * 1. Validate arguments
   */

  if (atkeys == NULL) {
    ret = 1;
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atkeys is NULL\n");
    return ret;
  }

  if (aes_pkam_public_key_str == NULL) {
    ret = 1;
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "aes_pkam_public_key_str is NULL\n");
    return ret;
  }

  if (aes_pkam_private_key_str == NULL) {
    ret = 1;
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "aes_pkam_private_key_str is NULL\n");
    return ret;
  }

  if (aes_encrypt_public_key_str == NULL) {
    ret = 1;
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "aes_encrypt_public_key_str is NULL\n");
    return ret;
  }

  if (aes_encrypt_private_key_str == NULL) {
    ret = 1;
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "aes_encrypt_private_key_str is NULL\n");
    return ret;
  }

  if (self_encryption_key_str == NULL) {
    ret = 1;
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "self_encryption_key_str is NULL\n");
    return ret;
  }

  if (aes_pkam_public_key_len == 0) {
    ret = 1;
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "aes_pkam_public_key_len is 0\n");
    return ret;
  }

  if (aes_pkam_private_key_len == 0) {
    ret = 1;
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "aes_pkam_private_key_len is 0\n");
    return ret;
  }

  if (aes_encrypt_public_key_len == 0) {
    ret = 1;
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "aes_encrypt_public_key_len is 0\n");
    return ret;
  }

  if (aes_encrypt_private_key_len == 0) {
    ret = 1;
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "aes_encrypt_private_key_len is 0\n");
    return ret;
  }

  if (self_encryption_key_str_len == 0) {
    ret = 1;
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "self_encryption_key_str_len is 0\n");
    return ret;
  }

  /*
   * 2. Initialize variables
   */

  // 2a. Use legacy IV
  // the atKeys are encrypted with bytes of 0s
  const size_t iv_size = ATCHOPS_IV_BUFFER_SIZE;
  unsigned char iv[iv_size];
  memset(iv, 0, sizeof(unsigned char) * iv_size);

  // holds the base64-decoded non-encrypted self encryption key
  // to use for decrypting the other RSA keys
  const size_t self_encryption_key_size = ATCHOPS_AES_256 / 8;
  unsigned char self_encryption_key[self_encryption_key_size];
  memset(self_encryption_key, 0, sizeof(unsigned char) * self_encryption_key_size);
  size_t self_encryption_key_len = 0;

  // temporarily holds the base64-encoded encrypted RSA key for decryption
  const size_t rsa_key_encrypted_size = 4096;
  unsigned char rsa_key_encrypted[rsa_key_encrypted_size];
  memset(rsa_key_encrypted, 0, sizeof(unsigned char) * rsa_key_encrypted_size);
  size_t rsa_key_encrypted_len = 0;

  // temporarily holds the base64-encoded decrypted RSA key
  const size_t rsa_key_decrypted_size = 4096;
  unsigned char rsa_key_decrypted[rsa_key_decrypted_size];
  memset(rsa_key_decrypted, 0, sizeof(unsigned char) * rsa_key_decrypted_size);
  size_t rsa_key_decrypted_len = 0;

  /*
   * 3. Prepare self encryption key for use
   */
  if ((ret = atchops_base64_decode((unsigned char *)self_encryption_key_str, self_encryption_key_str_len,
                                   self_encryption_key, self_encryption_key_size, &self_encryption_key_len)) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "tried base64 decoding selfencryption key: %d\n", ret);
    goto exit;
  }

  /*
   * 4. Decrypt and populate atkeys struct
   */

  // 4a. self encryption key
  if ((ret = atclient_atkeys_set_self_encryption_key_base64(atkeys, self_encryption_key_str,
                                                            self_encryption_key_str_len)) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR,
                 "set_self_encryption_key_base64: %d | failed to set self_encryption_key_str\n", ret);
    goto exit;
  }

  // 4b. pkam public key
  if ((ret = atchops_base64_decode((unsigned char *)aes_pkam_public_key_str, aes_pkam_public_key_len, rsa_key_encrypted,
                                   rsa_key_encrypted_size, &rsa_key_encrypted_len)) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "tried base64 decoding pkam public key: %d\n", ret);
    goto exit;
  }

  if ((ret = atchops_aes_ctr_decrypt(self_encryption_key, ATCHOPS_AES_256, iv, rsa_key_encrypted, rsa_key_encrypted_len,
                                     rsa_key_decrypted, rsa_key_decrypted_size, &rsa_key_decrypted_len)) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atchops_aes_ctr_decrypt: %d | failed to decrypt pkam public key\n",
                 ret);
    goto exit;
  }

  if ((ret = set_pkam_public_key_base64(atkeys, (const char *)rsa_key_decrypted, rsa_key_decrypted_len)) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "set_pkam_public_key_base64: %d | failed to set pkampublickeystr\n",
                 ret);
    goto exit;
  }

  memset(rsa_key_encrypted, 0, sizeof(unsigned char) * rsa_key_encrypted_size);
  memset(rsa_key_decrypted, 0, sizeof(unsigned char) * rsa_key_decrypted_size);
  memset(iv, 0, sizeof(unsigned char) * iv_size);

  // 4c. pkam private key
  if ((ret = atchops_base64_decode((unsigned char *)aes_pkam_private_key_str, aes_pkam_private_key_len,
                                   rsa_key_encrypted, rsa_key_encrypted_size, &rsa_key_encrypted_len)) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "tried base64 decoding pkam private key: %d\n", ret);
    goto exit;
  }

  if ((ret = atchops_aes_ctr_decrypt(self_encryption_key, ATCHOPS_AES_256, iv, rsa_key_encrypted, rsa_key_encrypted_len,
                                     rsa_key_decrypted, rsa_key_decrypted_size, &rsa_key_decrypted_len)) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR,
                 "atchops_aes_ctr_decrypt: %d | failed to decrypt pkam private key\n", ret);
    goto exit;
  }

  if ((ret = set_pkam_private_key_base64(atkeys, (const char *)rsa_key_decrypted, rsa_key_decrypted_len)) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR,
                 "set_pkam_private_key_base64: %d | failed to set pkamprivatekeystr\n", ret);
    goto exit;
  }

  memset(rsa_key_encrypted, 0, sizeof(unsigned char) * rsa_key_encrypted_size);
  memset(rsa_key_decrypted, 0, sizeof(unsigned char) * rsa_key_decrypted_size);
  memset(iv, 0, sizeof(unsigned char) * iv_size);

  // 4d. encrypt public key
  if ((ret = atchops_base64_decode((unsigned char *)aes_encrypt_public_key_str, aes_encrypt_public_key_len,
                                   rsa_key_encrypted, rsa_key_encrypted_size, &rsa_key_encrypted_len)) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "tried base64 decoding encrypt public key: %d\n", ret);
    goto exit;
  }

  if ((ret = atchops_aes_ctr_decrypt(self_encryption_key, ATCHOPS_AES_256, iv, rsa_key_encrypted, rsa_key_encrypted_len,
                                     rsa_key_decrypted, rsa_key_decrypted_size, &rsa_key_decrypted_len)) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR,
                 "atchops_aes_ctr_decrypt: %d | failed to decrypt encrypt public key\n", ret);
    goto exit;
  }

  if ((ret = set_encrypt_public_key_base64(atkeys, (const char *)rsa_key_decrypted, rsa_key_decrypted_len)) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR,
                 "set_encrypt_public_key_base64: %d | failed to set encryptpublickeystr\n", ret);
    goto exit;
  }

  memset(rsa_key_encrypted, 0, sizeof(unsigned char) * rsa_key_encrypted_size);
  memset(rsa_key_decrypted, 0, sizeof(unsigned char) * rsa_key_decrypted_size);
  memset(iv, 0, sizeof(unsigned char) * iv_size);

  // 4e. encrypt private key
  if ((ret = atchops_base64_decode((unsigned char *)aes_encrypt_private_key_str, aes_encrypt_private_key_len,
                                   rsa_key_encrypted, rsa_key_encrypted_size, &rsa_key_encrypted_len)) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "tried base64 decoding encrypt private key: %d\n", ret);
    goto exit;
  }

  if ((ret = atchops_aes_ctr_decrypt(self_encryption_key, ATCHOPS_AES_256, iv, rsa_key_encrypted, rsa_key_encrypted_len,
                                     rsa_key_decrypted, rsa_key_decrypted_size, &rsa_key_decrypted_len)) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR,
                 "atchops_aes_ctr_decrypt: %d | failed to decrypt encrypt private key\n", ret);
    goto exit;
  }

  if ((ret = set_encrypt_private_key_base64(atkeys, (const char *)rsa_key_decrypted, rsa_key_decrypted_len)) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR,
                 "set_encrypt_private_key_base64: %d | failed to set encryptprivatekeystr\n", ret);
    goto exit;
  }

  /*
   * 5. Populate rsakey structs
   */

  // 5a. pkam public key
  if ((ret = atchops_rsa_key_populate_public_key(&(atkeys->pkam_public_key), atkeys->pkam_public_key_base64,
                                                 strlen(atkeys->pkam_public_key_base64))) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR,
                 "atchops_rsa_key_populate_public_key: %d | failed to populate pkam public key\n", ret);
    goto exit;
  }

  // 5b. pkam private key
  if ((ret = atchops_rsa_key_populate_private_key(&(atkeys->pkam_private_key), atkeys->pkam_private_key_base64,
                                                  strlen(atkeys->pkam_private_key_base64))) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR,
                 "atchops_rsa_key_populate_private_key: %d | failed to populate pkam private key\n", ret);
    goto exit;
  }

  // 5c. encrypt public key
  if ((ret = atchops_rsa_key_populate_private_key(&(atkeys->encrypt_private_key), atkeys->encrypt_private_key_base64,
                                                  strlen(atkeys->encrypt_private_key_base64))) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR,
                 "atchops_rsa_key_populate_private_key: %d | failed to populate encrypt private key\n", ret);
    goto exit;
  }

  // 5d. encrypt private key
  if ((ret = atchops_rsa_key_populate_public_key(&(atkeys->encrypt_public_key), atkeys->encrypt_public_key_base64,
                                                 strlen(atkeys->encrypt_public_key_base64))) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR,
                 "atchops_rsa_key_populate_public_key: %d | failed to populate encrypt public key\n", ret);
    goto exit;
  }

  ret = 0;
  goto exit;

exit: { return ret; }
}

int atclient_atkeys_populate_from_atkeys_file(atclient_atkeys *atkeys, const atclient_atkeys_file *atkeys_file) {
  int ret = 1;

  ret = atclient_atkeys_populate_from_strings(
      atkeys, atkeys_file->aes_pkam_public_key_str, strlen(atkeys_file->aes_pkam_public_key_str),
      atkeys_file->aes_pkam_private_key_str, strlen(atkeys_file->aes_pkam_private_key_str),
      atkeys_file->aes_encrypt_public_key_str, strlen(atkeys_file->aes_encrypt_public_key_str),
      atkeys_file->aes_encrypt_private_key_str, strlen(atkeys_file->aes_encrypt_private_key_str),
      atkeys_file->self_encryption_key_str, strlen(atkeys_file->self_encryption_key_str));
  if (ret != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR,
                 "atclient_atkeys_populate_from_strings: %d | failed to populate from strings\n", ret);
    goto exit;
  }

  goto exit;

exit: { return ret; }
}

int atclient_atkeys_populate_from_path(atclient_atkeys *atkeys, const char *path) {
  int ret = 1;

  atclient_atkeys_file atkeys_file;
  atclient_atkeys_file_init(&atkeys_file);

  if ((ret = atclient_atkeys_file_from_path(&atkeys_file, path)) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR,
                 "atclient_atkeys_file_from_path: %d | failed to read file at path: %s\n", ret, path);
    goto exit;
  }

  if ((ret = atclient_atkeys_populate_from_atkeys_file(atkeys, &atkeys_file)) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR,
                 "atclient_atkeys_populate_from_atkeys_file: %d | failed to decrypt & populate struct \n", ret);
    goto exit;
  }

  goto exit;
exit: {
  atclient_atkeys_file_free(&atkeys_file);
  return ret;
}
}

int atclient_atkeys_populate_from_string(atclient_atkeys *atkeys, const char *file_string) {
  int ret = 1;

  atclient_atkeys_file atkeys_file;
  atclient_atkeys_file_init(&atkeys_file);

  if ((ret = atclient_atkeys_file_from_string(&atkeys_file, file_string)) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atclient_atkeys_file_from_string: %d\n", ret);
    goto exit;
  }

  if ((ret = atclient_atkeys_populate_from_atkeys_file(atkeys, &atkeys_file)) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR,
                 "atclient_atkeys_populate_from_atkeys_file: %d | failed to decrypt & populate struct \n", ret);
    goto exit;
  }

  ret = 0;
  goto exit;

exit: {
  atclient_atkeys_file_free(&atkeys_file);
  return ret;
}
}

static bool is_pkam_public_key_base64_initialized(atclient_atkeys *atkeys) {
  return atkeys->_initialized_fields[ATCLIENT_ATKEYS_PKAM_PUBLIC_KEY_INDEX] &
         ATCLIENT_ATKEYS_PKAM_PUBLIC_KEY_INITIALIZED;
}

static bool is_pkam_private_key_base64_initialized(atclient_atkeys *atkeys) {
  return atkeys->_initialized_fields[ATCLIENT_ATKEYS_PKAM_PRIVATE_KEY_INDEX] &
         ATCLIENT_ATKEYS_PKAM_PRIVATE_KEY_INITIALIZED;
}

static bool is_encrypt_public_key_base64_initialized(atclient_atkeys *atkeys) {
  return atkeys->_initialized_fields[ATCLIENT_ATKEYS_ENCRYPT_PUBLIC_KEY_INDEX] &
         ATCLIENT_ATKEYS_ENCRYPT_PUBLIC_KEY_INITIALIZED;
}

static bool is_encrypt_private_key_base64_initialized(atclient_atkeys *atkeys) {
  return atkeys->_initialized_fields[ATCLIENT_ATKEYS_ENCRYPT_PRIVATE_KEY_INDEX] &
         ATCLIENT_ATKEYS_ENCRYPT_PRIVATE_KEY_INITIALIZED;
}

static bool is_self_encryption_key_base64_initialized(atclient_atkeys *atkeys) {
  return atkeys->_initialized_fields[ATCLIENT_ATKEYS_SELF_ENCRYPTION_KEY_INDEX] &
         ATCLIENT_ATKEYS_SELF_ENCRYPTION_KEY_INITIALIZED;
}

static bool is_enrollment_id_initialized(atclient_atkeys *atkeys) {
  return atkeys->_initialized_fields[ATCLIENT_ATKEYS_ENROLLMENT_ID_INDEX] & ATCLIENT_ATKEYS_ENROLLMENT_ID_INITIALIZED;
}

static void set_pkam_public_key_base64_initialized(atclient_atkeys *atkeys, const bool initialized) {
  if (initialized) {
    atkeys->_initialized_fields[ATCLIENT_ATKEYS_PKAM_PUBLIC_KEY_INDEX] |= ATCLIENT_ATKEYS_PKAM_PUBLIC_KEY_INITIALIZED;
  } else {
    atkeys->_initialized_fields[ATCLIENT_ATKEYS_PKAM_PUBLIC_KEY_INDEX] &= ~ATCLIENT_ATKEYS_PKAM_PUBLIC_KEY_INITIALIZED;
  }
}

static void set_pkam_private_key_base64_initialized(atclient_atkeys *atkeys, const bool initialized) {
  if (initialized) {
    atkeys->_initialized_fields[ATCLIENT_ATKEYS_PKAM_PRIVATE_KEY_INDEX] |= ATCLIENT_ATKEYS_PKAM_PRIVATE_KEY_INITIALIZED;
  } else {
    atkeys->_initialized_fields[ATCLIENT_ATKEYS_PKAM_PRIVATE_KEY_INDEX] &=
        ~ATCLIENT_ATKEYS_PKAM_PRIVATE_KEY_INITIALIZED;
  }
}

static void set_encrypt_public_key_base64_initialized(atclient_atkeys *atkeys, const bool initialized) {
  if (initialized) {
    atkeys->_initialized_fields[ATCLIENT_ATKEYS_ENCRYPT_PUBLIC_KEY_INDEX] |=
        ATCLIENT_ATKEYS_ENCRYPT_PUBLIC_KEY_INITIALIZED;
  } else {
    atkeys->_initialized_fields[ATCLIENT_ATKEYS_ENCRYPT_PUBLIC_KEY_INDEX] &=
        ~ATCLIENT_ATKEYS_ENCRYPT_PUBLIC_KEY_INITIALIZED;
  }
}

static void set_encrypt_privatekey_base64_initialized(atclient_atkeys *atkeys, const bool initialized) {
  if (initialized) {
    atkeys->_initialized_fields[ATCLIENT_ATKEYS_ENCRYPT_PRIVATE_KEY_INDEX] |=
        ATCLIENT_ATKEYS_ENCRYPT_PRIVATE_KEY_INITIALIZED;
  } else {
    atkeys->_initialized_fields[ATCLIENT_ATKEYS_ENCRYPT_PRIVATE_KEY_INDEX] &=
        ~ATCLIENT_ATKEYS_ENCRYPT_PRIVATE_KEY_INITIALIZED;
  }
}

static void set_self_encryption_key_base64_initialized(atclient_atkeys *atkeys, const bool initialized) {
  if (initialized) {
    atkeys->_initialized_fields[ATCLIENT_ATKEYS_SELF_ENCRYPTION_KEY_INDEX] |=
        ATCLIENT_ATKEYS_SELF_ENCRYPTION_KEY_INITIALIZED;
  } else {
    atkeys->_initialized_fields[ATCLIENT_ATKEYS_SELF_ENCRYPTION_KEY_INDEX] &=
        ~ATCLIENT_ATKEYS_SELF_ENCRYPTION_KEY_INITIALIZED;
  }
}

static void set_enrollment_id_initialized(atclient_atkeys *atkeys, const bool initialized) {
  if (initialized) {
    atkeys->_initialized_fields[ATCLIENT_ATKEYS_ENROLLMENT_ID_INDEX] |= ATCLIENT_ATKEYS_ENROLLMENT_ID_INITIALIZED;
  } else {
    atkeys->_initialized_fields[ATCLIENT_ATKEYS_ENROLLMENT_ID_INDEX] &= ~ATCLIENT_ATKEYS_ENROLLMENT_ID_INITIALIZED;
  }
}

static void unset_pkam_public_key_base64(atclient_atkeys *atkeys) {
  if (is_pkam_public_key_base64_initialized(atkeys)) {
    free(atkeys->pkam_public_key_base64);
  }
  atkeys->pkam_public_key_base64 = NULL;
  set_pkam_public_key_base64_initialized(atkeys, false);
}

static void unset_pkam_private_key_base64(atclient_atkeys *atkeys) {
  if (is_pkam_private_key_base64_initialized(atkeys)) {
    free(atkeys->pkam_private_key_base64);
  }
  atkeys->pkam_private_key_base64 = NULL;
  set_pkam_private_key_base64_initialized(atkeys, false);
}

static void unset_encrypt_public_key_base64(atclient_atkeys *atkeys) {
  if (is_encrypt_public_key_base64_initialized(atkeys)) {
    free(atkeys->encrypt_public_key_base64);
  }
  atkeys->encrypt_public_key_base64 = NULL;
  set_encrypt_public_key_base64_initialized(atkeys, false);
}

static void unset_encrypt_private_key_base64(atclient_atkeys *atkeys) {
  if (is_encrypt_private_key_base64_initialized(atkeys)) {
    free(atkeys->encrypt_private_key_base64);
  }
  atkeys->encrypt_private_key_base64 = NULL;
  set_encrypt_privatekey_base64_initialized(atkeys, false);
}

static void unset_self_encryption_key_base64(atclient_atkeys *atkeys) {
  if (is_self_encryption_key_base64_initialized(atkeys) && atkeys->self_encryption_key_base64 != NULL) {
    free(atkeys->self_encryption_key_base64);
  }
  atkeys->self_encryption_key_base64 = NULL;
  set_self_encryption_key_base64_initialized(atkeys, false);
}

static void unset_enrollment_id(atclient_atkeys *atkeys) {
  if (is_enrollment_id_initialized(atkeys)) {
    free(atkeys->enrollment_id);
  }
  atkeys->enrollment_id = NULL;
  set_enrollment_id_initialized(atkeys, false);
}

static int set_pkam_public_key_base64(atclient_atkeys *atkeys, const char *pkam_public_key_base64,
                                      const size_t pkam_public_key_len) {
  int ret = 1;

  if (is_pkam_public_key_base64_initialized(atkeys)) {
    unset_pkam_public_key_base64(atkeys);
  }

  const size_t pkam_publickey_size = pkam_public_key_len + 1;
  atkeys->pkam_public_key_base64 = (char *)malloc(sizeof(char) * (pkam_publickey_size));
  if (atkeys->pkam_public_key_base64 == NULL) {
    ret = 1;
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR,
                 "malloc: %d | failed to allocate memory for pkam_public_key_base64\n", ret);
    goto exit;
  }

  memcpy(atkeys->pkam_public_key_base64, pkam_public_key_base64, pkam_public_key_len);
  atkeys->pkam_public_key_base64[pkam_public_key_len] = '\0';

  set_pkam_public_key_base64_initialized(atkeys, true);

  ret = 0;
  goto exit;

exit: { return ret; }
}

static int set_pkam_private_key_base64(atclient_atkeys *atkeys, const char *pkam_private_key_base64,
                                       const size_t pkam_private_key_len) {
  int ret = 1;

  if (is_pkam_private_key_base64_initialized(atkeys)) {
    unset_pkam_private_key_base64(atkeys);
  }

  const size_t pkam_private_key_size = pkam_private_key_len + 1;
  atkeys->pkam_private_key_base64 = (char *)malloc(sizeof(char) * (pkam_private_key_size));
  if (atkeys->pkam_private_key_base64 == NULL) {
    ret = 1;
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR,
                 "malloc: %d | failed to allocate memory for pkam_private_key_base64\n", ret);
    goto exit;
  }

  memcpy(atkeys->pkam_private_key_base64, pkam_private_key_base64, pkam_private_key_len);
  atkeys->pkam_private_key_base64[pkam_private_key_len] = '\0';

  set_pkam_private_key_base64_initialized(atkeys, true);

  ret = 0;
  goto exit;
exit: { return ret; }
}

static int set_encrypt_public_key_base64(atclient_atkeys *atkeys, const char *encrypt_public_key_base64,
                                         const size_t encrypt_public_key_len) {
  int ret = 1;

  if (is_encrypt_public_key_base64_initialized(atkeys)) {
    unset_encrypt_public_key_base64(atkeys);
  }

  const size_t encrypt_public_key_size = encrypt_public_key_len + 1;
  atkeys->encrypt_public_key_base64 = (char *)malloc(sizeof(char) * (encrypt_public_key_size));
  if (atkeys->encrypt_public_key_base64 == NULL) {
    ret = 1;
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR,
                 "malloc: %d | failed to allocate memory for encrypt_public_key_base64\n", ret);
    goto exit;
  }

  memcpy(atkeys->encrypt_public_key_base64, encrypt_public_key_base64, encrypt_public_key_len);
  atkeys->encrypt_public_key_base64[encrypt_public_key_len] = '\0';

  set_encrypt_public_key_base64_initialized(atkeys, true);

  ret = 0;
  goto exit;
exit: { return ret; }
}

static int set_encrypt_private_key_base64(atclient_atkeys *atkeys, const char *encrypt_private_key_base64,
                                          const size_t encrypt_private_key_len) {
  int ret = 1;

  if (is_encrypt_private_key_base64_initialized(atkeys)) {
    unset_encrypt_private_key_base64(atkeys);
  }

  const size_t encrypt_private_key_size = encrypt_private_key_len + 1;
  atkeys->encrypt_private_key_base64 = (char *)malloc(sizeof(char) * (encrypt_private_key_size));
  if (atkeys->encrypt_private_key_base64 == NULL) {
    ret = 1;
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR,
                 "malloc: %d | failed to allocate memory for encrypt_private_key_base64\n", ret);
    goto exit;
  }

  memcpy(atkeys->encrypt_private_key_base64, encrypt_private_key_base64, encrypt_private_key_len);
  atkeys->encrypt_private_key_base64[encrypt_private_key_len] = '\0';

  set_encrypt_privatekey_base64_initialized(atkeys, true);

  ret = 0;
  goto exit;
exit: { return ret; }
}

static int set_self_encryption_key_base64(atclient_atkeys *atkeys, const char *self_encryption_key_base64,
                                          const size_t self_encryption_key_len) {
  int ret = 1;

  if (self_encryption_key_base64 == NULL || self_encryption_key_len == 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "Invalid self encryption key or key length\n");
    return 1;
  }

  if (is_self_encryption_key_base64_initialized(atkeys)) {
    unset_self_encryption_key_base64(atkeys);
  }

  const size_t self_encryption_key_size = self_encryption_key_len + 1;
  atkeys->self_encryption_key_base64 = (char *)malloc(self_encryption_key_size);
  if (atkeys->self_encryption_key_base64 == NULL) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "Failed to allocate memory for self_encryption_key_base64\n");
    return 1;
  }

  memcpy(atkeys->self_encryption_key_base64, self_encryption_key_base64, self_encryption_key_len);
  atkeys->self_encryption_key_base64[self_encryption_key_len] = '\0'; // Null-terminate the string

  set_self_encryption_key_base64_initialized(atkeys, true);

  ret = 0;
  return ret;
}

static int set_enrollment_id(atclient_atkeys *atkeys, const char *enrollment_id, const size_t enrollment_id_len) {
  int ret = 1;

  if (enrollment_id == NULL || enrollment_id_len == 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "Invalid enrollment id or id length\n");
    return 1;
  }

  if (is_enrollment_id_initialized(atkeys)) {
    unset_enrollment_id(atkeys);
  }

  // Allocate memory for the enrollment id
  const size_t enrollment_id_size = enrollment_id_len + 1;
  atkeys->enrollment_id = (char *)malloc(enrollment_id_size);
  if (atkeys->enrollment_id == NULL) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "Failed to allocate memory for enrollment_id\n");
    return 1;
  }

  memcpy(atkeys->enrollment_id, enrollment_id, enrollment_id_len);
  atkeys->enrollment_id[enrollment_id_len] = '\0'; // Null-terminate the string

  set_enrollment_id_initialized(atkeys, true);

  ret = 0;
  return ret;
}
