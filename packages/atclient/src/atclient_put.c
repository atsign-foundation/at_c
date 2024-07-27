#include "atclient/atclient.h"
#include "atclient/atkey.h"
#include "atclient/constants.h"
#include "atclient/encryption_key_helpers.h"
#include "atclient/string_utils.h"
#include "atlogger/atlogger.h"
#include <atchops/aes_ctr.h>
#include <atchops/base64.h>
#include <atchops/iv.h>
#include <atchops/rsa.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>

#define TAG "atclient_put"

static int atclient_put_validate_args(const atclient *ctx, const atclient_atkey *atkey, const char *value,
                                      const int *commit_id);

int atclient_put(atclient *ctx, atclient_atkey *atkey, const char *value, int *commit_id) {
  int ret = 1;

  /*
   * 1. Check if valid arguments were passed
   */
  if ((ret = atclient_put_validate_args(ctx, atkey, value, commit_id)) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atclient_put_validate_args: %d\n", ret);
    return ret;
  }

  /*
   * 2. Allocate variables
   */
  const size_t value_len = strlen(value);

  char *atkey_str = NULL;
  char *update_cmd = NULL;
  char *metadata_protocol_str = NULL;

  const short iv_size = ATCHOPS_IV_BUFFER_SIZE;
  unsigned char iv[ATCHOPS_IV_BUFFER_SIZE];
  memset(iv, 0, sizeof(unsigned char) * iv_size);

  const size_t iv_base64_size = atchops_base64_encoded_size(iv_size) + 1;
  char iv_base64[iv_base64_size];
  memset(iv_base64, 0, sizeof(char) * iv_base64_size);

  const size_t ciphertext_size = atchops_aes_ctr_ciphertext_size(value_len) + 1;
  unsigned char ciphertext[ciphertext_size];
  memset(ciphertext, 0, sizeof(unsigned char) * ciphertext_size);
  size_t ciphertext_len = 0;

  const size_t ciphertext_base64_size = atchops_base64_encoded_size(ciphertext_size) + 1;
  char ciphertext_base64[ciphertext_base64_size];
  memset(ciphertext_base64, 0, sizeof(char) * ciphertext_base64_size);
  size_t ciphertextbase64_len = 0;

  const size_t shared_encryption_key_size = ATCHOPS_AES_256 / 8;
  unsigned char shared_encryption_key[shared_encryption_key_size];
  memset(shared_encryption_key, 0, sizeof(unsigned char) * shared_encryption_key_size);

  const size_t shared_encryption_key_base64_size = atchops_base64_encoded_size(shared_encryption_key_size) + 1;
  char shared_encryption_key_base64[shared_encryption_key_base64_size];
  memset(shared_encryption_key_base64, 0, sizeof(char) * shared_encryption_key_base64_size);
  size_t shared_encryption_key_base64_len = 0;

  const size_t recv_size = 4096; // sufficient buffer size to 1. receive data from a `llookup:shared_key@<>` and 2. to
                                 // receive commmit id from `update:`
  unsigned char *recv = NULL;
  if (!ctx->async_read) {
    recv = malloc(sizeof(unsigned char) * recv_size);
    if (recv == NULL) {
      ret = 1;
      atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "Failed to allocate memory for recv\n");
      goto exit;
    }
    memset(recv, 0, sizeof(unsigned char) * recv_size);
  }
  size_t recv_len = 0;

  /*
   * 3. Build `update:` command
   *    3a. Encrypt the value, if needed.
   *        3a.1 If the AtKey is a publickey, no encryption is needed.
   *        3a.2 If the AtKey is a selfkey, encrypt with self encryption key.
   *        3a.3 If the AtKey is a sharedkey, encrypt with shared encryption key.
   *          If the shared encryption key doesn't exist, create one for us and one for the other person.
   *          If the shared encryption key does exist, encrypt with it.
   *    3b. Build the command
   */

  const atclient_atkey_type atkey_type = atclient_atkey_get_type(atkey);

  if (atkey_type == ATCLIENT_ATKEY_TYPE_PUBLIC_KEY) {
    // 3a.1 no encryption
    memcpy(ciphertext_base64, value, value_len);
    ciphertextbase64_len = value_len;
  } else if (atkey_type == ATCLIENT_ATKEY_TYPE_SELF_KEY) {
    // 3a.2 encrypt with self encryption key
    const size_t selfencryptionkeysize = ATCHOPS_AES_256 / 8;
    unsigned char selfencryptionkey[selfencryptionkeysize];
    memset(selfencryptionkey, 0, sizeof(unsigned char) * selfencryptionkeysize);
    size_t selfencryptionkeylen = 0;

    if ((ret = atchops_base64_decode((const unsigned char *)ctx->atkeys.self_encryption_key_base64,
                                     strlen(ctx->atkeys.self_encryption_key_base64), selfencryptionkey,
                                     selfencryptionkeysize, &selfencryptionkeylen)) != 0) {
      atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atchops_base64_decode: %d\n", ret);
      goto exit;
    }

    if ((ret = atchops_aes_ctr_encrypt(selfencryptionkey, ATCHOPS_AES_256, iv, (unsigned char *)value, value_len,
                                       ciphertext, ciphertext_size, &ciphertext_len)) != 0) {
      atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atchops_aes_ctr_encrypt: %d\n", ret);
      goto exit;
    }

    if ((ret = atchops_base64_encode(ciphertext, ciphertext_len, (unsigned char *)ciphertext_base64,
                                     ciphertext_base64_size, &ciphertextbase64_len)) != 0) {
      atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atchops_base64_encode: %d\n", ret);
      goto exit;
    }
  } else if (atkey_type == ATCLIENT_ATKEY_TYPE_SHARED_KEY) {
    // 3aA.3 encrypt with shared encryption key

    // get our AES shared key
    // if it doesn't exist, create one for us and create one for the other person
    // create one for us -> encrypted with our self encryption key
    // create one for the other person -> encrypted with their public encryption key
    char *recipient_atsign_with_at = NULL;

    if ((ret = atclient_string_utils_atsign_with_at(atkey->shared_with, &recipient_atsign_with_at)) != 0) {
      atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atclient_stringutils_concat_at_sign_with_at: %d\n", ret);
      goto shared_key_exit;
    }

    if ((ret = atclient_get_shared_encryption_key_shared_by_me(ctx, recipient_atsign_with_at, shared_encryption_key)) !=
        0) {
      atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_DEBUG, "atclient_get_shared_encryption_key_shared_by_me: %d\n", ret);
      atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_DEBUG, "Creating shared encryption key\n");
      if ((ret = atclient_create_shared_encryption_key_pair_for_me_and_other(ctx, recipient_atsign_with_at,
                                                                             shared_encryption_key)) != 0) {
        atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR,
                     "atclient_create_shared_encryption_key_pair_for_me_and_other: %d\n", ret);
        goto shared_key_exit;
      }
      atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_DEBUG, "Created shared encryption key successfully\n");
    }

    if ((ret = atchops_iv_generate(iv)) != 0) {
      atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atchops_iv_generate: %d\n", ret);
      goto shared_key_exit;
    }

    if ((ret = atchops_base64_encode(iv, ATCHOPS_IV_BUFFER_SIZE, (unsigned char *)iv_base64, iv_base64_size, NULL)) !=
        0) {
      atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atchops_base64_encode: %d\n", ret);
      goto shared_key_exit;
    }

    if ((ret = atclient_atkey_metadata_set_iv_nonce(&(atkey->metadata), iv_base64)) != 0) {
      atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atclient_atkey_metadata_set_ivnonce: %d\n", ret);
      goto shared_key_exit;
    }

    if ((ret = atchops_aes_ctr_encrypt(shared_encryption_key, ATCHOPS_AES_256, iv, (unsigned char *)value, value_len,
                                       ciphertext, ciphertext_size, &ciphertext_len)) != 0) {
      atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atchops_aes_ctr_encrypt: %d\n", ret);
      goto shared_key_exit;
    }

    if ((ret = atchops_base64_encode(ciphertext, ciphertext_len, (unsigned char *)ciphertext_base64,
                                     ciphertext_base64_size, &ciphertextbase64_len)) != 0) {
      atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atchops_base64_encode: %d\n", ret);
      goto shared_key_exit;
    }

  shared_key_exit: {
    free(recipient_atsign_with_at);
    if (ret != 0) {
      goto exit;
    }
  }
  }

  // 3b. Build the command

  if ((ret = atclient_atkey_to_string(atkey, &atkey_str)) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atclient_atkey_to_string: %d\n", ret);
    goto exit;
  }
  const size_t atkey_strlen = strlen(atkey_str);

  if ((ret = atclient_atkey_metadata_to_protocol_str(&(atkey->metadata), &(metadata_protocol_str))) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atclient_atkey_metadata_to_protocolstr: %d\n", ret);
    goto exit;
  }
  const size_t metadataprotocolstrlen = strlen(metadata_protocol_str);

  const size_t update_cmd_size = strlen("update: \r\n") + metadataprotocolstrlen + atkey_strlen + ciphertextbase64_len +
                                 1; // + 1 for null terminator
  update_cmd = malloc(sizeof(char) * update_cmd_size);
  if (update_cmd == NULL) {
    ret = 1;
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "Failed to allocate memory for update_cmd\n");
    goto exit;
  }
  memset(update_cmd, 0, sizeof(char) * update_cmd_size);
  snprintf(update_cmd, update_cmd_size, "update%.*s:%.*s %.*s\r\n", (int)metadataprotocolstrlen, metadata_protocol_str,
           (int)atkey_strlen, atkey_str, (int)ciphertextbase64_len, ciphertext_base64);

  /*
   * 4. Send the command
   */
  if ((ret = atclient_connection_send(&(ctx->atserver_connection), (unsigned char *)update_cmd, update_cmd_size - 1,
                                      recv, recv_size, &recv_len)) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atclient_connection_send: %d\n", ret);
    goto exit;
  }

  if (ctx->async_read) {
    goto exit;
  }

  if (!atclient_string_utils_starts_with((char *)recv, "data:")) {
    ret = 1;
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "recv was \"%.*s\" and did not have prefix \"data:\"\n",
                 (int)recv_len, recv);
    goto exit;
  }

  /*
   * 5. Return the commit id.
   */

  if (commit_id != NULL) {
    char *recvwithoutdata = (char *)recv + 5;
    *commit_id = atoi(recvwithoutdata);
  }

  ret = 0;
  goto exit;
exit: {
  if (!ctx->async_read) {
    free(recv);
  }
  free(update_cmd);
  free(metadata_protocol_str);
  free(atkey_str);
  return ret;
}
}

static int atclient_put_validate_args(const atclient *ctx, const atclient_atkey *atkey, const char *value,
                                      const int *commit_id) {
  int ret = 1;
  if (ctx == NULL) {
    ret = 1;
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atclient is NULL\n");
    goto exit;
  }

  if (!atclient_is_atserver_connection_started(ctx)) {
    ret = 1;
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atserver connection not started\n");
    goto exit;
  }

  if (!atclient_is_atsign_initialized(ctx)) {
    ret = 1;
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atsign is not allocated. Make sure to PKAM authenticate first\n");
    goto exit;
  }

  if (atkey == NULL) {
    ret = 1;
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atkey is NULL\n");
    goto exit;
  }

  if (value == NULL) {
    ret = 1;
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "value is NULL\n");
    goto exit;
  }

  if (!atclient_atkey_is_shared_by_initialized(atkey) || strlen(atkey->shared_by) <= 0) {
    ret = 1;
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atkey's shared_by is not initialized or is empty\n");
    goto exit;
  }

  if (strcmp(atkey->shared_by, ctx->atsign) != 0) {
    ret = 1;
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atkey's shared_by is not atclient's atsign\n");
    goto exit;
  }

  if (ctx->async_read) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR,
                 "atclient_put cannot be called from an async_read atclient, it will cause a race condition\n");
    goto exit;
  }
  ret = 0;
  goto exit;
exit: { return ret; }
}