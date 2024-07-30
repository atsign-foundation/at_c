#include "atchops/aes_ctr.h"
#include <atlogger/atlogger.h>
#include "atchops/mbedtls.h"
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define TAG "aes_ctr"

int atchops_aes_ctr_encrypt(const unsigned char *key, const enum atchops_aes_size key_bits, unsigned char *iv,
                            const unsigned char *plaintext, // plaintext to encrypt
                            const size_t plaintext_len,
                            unsigned char *ciphertext,    // allocated buffer to populate
                            const size_t ciphertext_size, // number of total bytes allocated in the buffer
                            size_t *ciphertext_len        // written actual length in the buffer
) {
  int ret = 1;

  /*
   * 1. Validate arguments
   */
  if (key == NULL) {
    ret = 1;
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "key is NULL\n");
    return ret;
  }

  if (key_bits != ATCHOPS_AES_256) {
    ret = 1;
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "Unsupported keybits\n");
    return ret;
  }

  if (iv == NULL) {
    ret = 1;
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "iv is NULL\n");
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

  if (ciphertext_len == NULL) {
    ret = 1;
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "ciphertext_len is NULL\n");
    return ret;
  }

  if (ciphertext_size < plaintext_len) {
    ret = 1;
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "ciphertext_size is less than plaintext_len\n");
    return ret;
  }

  /*
   * 2. Variables
   */
  mbedtls_aes_context aes;
  mbedtls_aes_init(&aes);

  unsigned char *plaintext_padded = NULL; // will contain the plaintext with padded trialing bytes
  unsigned char stream_block[16];

  /*
   * 3. Pad plaintext
   */
  size_t plaintext_padded_len; // the length of the plain text + padding (no null terminator)

  const int num_pad_bytes_to_add = 16 - (plaintext_len % 16);
  const unsigned char pad_val = num_pad_bytes_to_add;

  plaintext_padded_len = plaintext_len + num_pad_bytes_to_add;

  if ((plaintext_padded = malloc(sizeof(unsigned char) * (plaintext_padded_len + 1))) == NULL) {
    ret = 1;
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "Failed to allocate memory for plaintext_padded\n");
    goto exit;
  }
  memcpy(plaintext_padded, plaintext, plaintext_len);
  memset(plaintext_padded + plaintext_len, pad_val, num_pad_bytes_to_add);
  plaintext_padded[plaintext_padded_len] = '\0';

  /*
   * 3. Prepare AES context
   */
  if ((ret = mbedtls_aes_setkey_enc(&aes, key, key_bits)) != 0) {
    goto exit;
  }

  /*
   * 4. Encrypt
   */
  size_t nc_off = 0;
  memset(stream_block, 0, sizeof(unsigned char) * 16);
  memset(ciphertext, 0, sizeof(unsigned char) * ciphertext_size); // clear the buffer
  if ((ret = mbedtls_aes_crypt_ctr(&aes, plaintext_padded_len, &nc_off, iv, stream_block, plaintext_padded,
                                   ciphertext)) != 0) {
    goto exit;
  }

  if (ciphertext_len != NULL) {
    *ciphertext_len = plaintext_padded_len;
  }

  ret = 0;
  goto exit;
exit: {
  free(plaintext_padded);
  mbedtls_aes_free(&aes);
  return ret;
}
}

int atchops_aes_ctr_decrypt(const unsigned char *key, const enum atchops_aes_size key_bits, unsigned char *iv,
                            const unsigned char *ciphertext, const size_t ciphertext_len, unsigned char *plaintext,
                            const size_t plaintext_size, size_t *plaintext_len) {
  int ret = 1;

  /*
   * 1. Validate arguments
   */

  if (key == NULL) {
    ret = 1;
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "key is NULL\n");
    return ret;
  }

  if (key_bits != ATCHOPS_AES_256) {
    ret = 1;
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "Unsupported keybits\n");
    return ret;
  }

  if (iv == NULL) {
    ret = 1;
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "iv is NULL\n");
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

  if (plaintext_size <= 0) {
    ret = 1;
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "plaintext_size is less than or equal to 0\n");
    return ret;
  }

  if (plaintext_size < ciphertext_len) {
    ret = 1;
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "plaintext_size is less than ciphertext_len\n");
    return ret;
  }

  /*
   * 2. Variables
   */
  mbedtls_aes_context aes;
  mbedtls_aes_init(&aes);

  unsigned char *plaintext_padded = NULL;
  unsigned char stream_block[16];

  /*
   * 3. Prepare AES context
   */
  if ((ret = mbedtls_aes_setkey_enc(&aes, key, key_bits)) != 0) {
    goto exit;
  }

  /*
   * 4. Allocate buffers required for decryption
   */
  size_t nc_off = 0;
  memset(stream_block, 0, sizeof(unsigned char) * 16);

  const size_t plaintextpaddedsize = plaintext_size + 16;
  if ((plaintext_padded = malloc(sizeof(unsigned char) * plaintextpaddedsize)) == NULL) {
    ret = 1;
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "Failed to allocate memory for plaintext_padded\n");
    goto exit;
  }
  memset(plaintext_padded, 0, sizeof(unsigned char) * plaintextpaddedsize);
  size_t plaintext_padded_len = 0;

  /*
   * 3. Decrypt
   */
  if ((ret = mbedtls_aes_crypt_ctr(&aes, ciphertext_len, &nc_off, iv, stream_block, ciphertext, plaintext_padded)) !=
      0) {
    goto exit;
  }

  /*
   * 4. Remove padding
   */
  while (*(plaintext_padded + plaintext_padded_len++) != '\0')
    ;
  --plaintext_padded_len; // don't count the null terminator

  // IBM PKCS Padding method states that there is always at least 1 padded value:
  // https://www.ibm.com/docs/en/zos/2.4.0?topic=rules-pkcs-padding-method the value of the padded byte is always the
  // number of padded bytes to expect, pad_val == num_padded_bytes
  unsigned char pad_val = plaintext_padded[plaintext_padded_len - 1];

  if (pad_val < 1 || pad_val > 16) {
    ret = 1;
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "Invalid pad_val: %d\n", pad_val);
    goto exit;
  }

  /*
   * 5. Return outputs
   */
  if (plaintext_len != NULL) {
    *plaintext_len = plaintext_padded_len - pad_val;
  }
  memcpy(plaintext, plaintext_padded, *plaintext_len);

  goto exit;
exit: {
  free(plaintext_padded);
  mbedtls_aes_free(&aes);
  return ret;
}
}

size_t atchops_aes_ctr_ciphertext_size(const size_t plaintext_len) { return ((plaintext_len + 15) & ~0xF) + 16; }

size_t atchops_aes_ctr_plaintext_size(const size_t ciphertext_len) { return ((ciphertext_len + 15) & ~0xF) + 16; }
