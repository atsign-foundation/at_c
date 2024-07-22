#include "atclient/encryption_key_helpers.h"
#include "atchops/aes.h"
#include "atchops/base64.h"
#include "atclient/atclient.h"
#include "atclient/atkeys.h"
#include "atclient/constants.h"
#include "atclient/stringutils.h"
#include "atlogger/atlogger.h"
#include <stdlib.h>
#include <string.h>

#define TAG "encryption_key_helpers"

int atclient_get_public_encryption_key(atclient *ctx, const char *atsign, char **public_encryption_key) {

  int ret = 1;

  /*
   * 1. Validate arguments
   */
  if (ctx == NULL) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "ctx is NULL\n");
    return ret;
  }

  if (atsign == NULL) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atsign is NULL\n");
    return ret;
  }

  if (public_encryption_key == NULL) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "public_encryption_key is NULL\n");
    return ret;
  }

  /*
   * 2. Variables
   */

  char *atsign_with_at = NULL;
  char *atsign_without_at = NULL;

  char *command = NULL;

  const size_t recvsize = 1024; // sufficient buffer size to receive the public key
  unsigned char recv[recvsize];
  memset(recv, 0, sizeof(unsigned char) * recvsize);
  size_t recvlen = 0;

  /*
   * 3. Generate plookup command
   */
  if ((ret = atclient_stringutils_atsign_with_at(atsign, &atsign_with_at)) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atclient_stringutils_atsign_with_at: %d\n", ret);
    goto exit;
  }

  if ((ret = atclient_stringutils_atsign_without_at(atsign_with_at, &atsign_without_at)) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atclient_stringutils_atsign_without_at: %d\n", ret);
    goto exit;
  }

  const size_t commandsize = strlen("plookup:publickey") + strlen(atsign_with_at) + strlen("\r\n") + 1;
  if ((command = (char *)malloc(sizeof(char) * commandsize)) == NULL) {
    ret = 1;
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "Failed to allocate memory for command\n");
    goto exit;
  }
  snprintf(command, commandsize, "plookup:publickey%s\r\n", atsign_with_at);

  /*
   * 4. Send command to atserver
   */
  if ((ret = atclient_connection_send(&(ctx->atserver_connection), (unsigned char *)command, commandsize - 1, recv,
                                      recvsize, &recvlen)) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atclient_connection_send: %d\n", ret);
    goto exit;
  }

  /*
   * 5. Parse repsonse
   */
  char *response = (char *)recv;

  if (!atclient_stringutils_starts_with(response, "data:")) {
    if (atclient_stringutils_starts_with((char *)recv, "error:AT0015-key not found")) {
      ret = ATCLIENT_ERR_AT0015_KEY_NOT_FOUND;
      atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atchops_rsa_decrypt: %d; error:AT0015-key not found\n", ret);
      goto exit;
    }
  }

  char *response_without_data = response + 5; // skip "data:"

  /*
   * 6. Allocate memory for public_encryption_key and give output to caller
   */
  const size_t public_encryption_key_size = strlen(response_without_data) + 1;
  if ((*public_encryption_key = (char *)malloc(sizeof(char) * public_encryption_key_size)) == NULL) {
    ret = 1;
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "Failed to allocate memory for public_encryption_key\n");
    goto exit;
  }

  memcpy(*public_encryption_key, response_without_data, public_encryption_key_size);
  *public_encryption_key[public_encryption_key_size - 1] = '\0';

  ret = 0;
exit: { return ret; }
}

int atclient_get_shared_encryption_key_shared_by_me(atclient *ctx, const char *recipient_atsign,
                                                    unsigned char *shared_encryption_key_shared_by_me) {
  int ret = 1;

  /*
   * 1. Validate arguments
   */
  if (ctx == NULL) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "ctx is NULL\n");
    return ret;
  }

  if (recipient_atsign == NULL) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "recipient_atsign is NULL\n");
    return ret;
  }

  if (shared_encryption_key_shared_by_me == NULL) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "shared_encryption_key_shared_by_me is NULL\n");
    return ret;
  }

  /*
   * 2. Variables
   */
  char *sender_atsign_with_at = NULL;
  char *recipient_atsign_with_at = NULL;

  char *command = NULL;

  const size_t recvsize = 1024;
  unsigned char recv[recvsize];

  const size_t key_raw_encrypted_size = 1024;
  unsigned char key_raw_encrypted[key_raw_encrypted_size];
  memset(key_raw_encrypted, 0, sizeof(unsigned char) * key_raw_encrypted_size);
  size_t key_raw_encrypted_len = 0;

  const size_t key_raw_decrypted_size = 1024;
  unsigned char key_raw_decrypted[key_raw_decrypted_size];
  memset(key_raw_decrypted, 0, sizeof(unsigned char) * key_raw_decrypted_size);
  size_t key_raw_decrypted_len = 0;

  /*
   * 3. Build llookup: command
   */
  if ((ret = atclient_stringutils_atsign_with_at(ctx->atsign, &sender_atsign_with_at)) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atclient_stringutils_atsign_with_at: %d\n", ret);
    goto exit;
  }

  if ((ret = atclient_stringutils_atsign_with_at(recipient_atsign, &recipient_atsign_with_at)) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atclient_stringutils_atsign_with_at: %d\n", ret);
    goto exit;
  }

  char *sender_atsign_without_at = sender_atsign_with_at + 1;
  char *recipient_atsign_without_at = recipient_atsign_with_at + 1;

  // llookup:shared_key.recipient_atsign@myatsign
  const short commandsize = strlen("llookup:shared_key.") + strlen(recipient_atsign_without_at) +
                            strlen(sender_atsign_with_at) + strlen("\r\n") + 1;
  if ((command = (char *)malloc(sizeof(char) * commandsize)) == NULL) {
    ret = 1;
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "Failed to allocate memory for command\n");
    goto exit;
  }
  snprintf(command, commandsize, "llookup:shared_key.%s%s\r\n", recipient_atsign_without_at, sender_atsign_with_at);

  /*
   * 4. Send command to atserver
   */
  memset(recv, 0, sizeof(unsigned char) * recvsize);
  size_t recvlen = 0;
  if ((ret = atclient_connection_send(&(ctx->atserver_connection), (unsigned char *)command, commandsize - 1, recv,
                                      recvsize, &recvlen)) != 0) {
    ret = 1;
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atclient_connection_send: %d\n", ret);
    goto exit;
  }

  /*
   * 5. Parse response
   */
  char *response = (char *)recv;

  if (!atclient_stringutils_starts_with(response, "data:")) {
    if (atclient_stringutils_starts_with(response, "error:AT0015-key not found")) {
      ret = ATCLIENT_ERR_AT0015_KEY_NOT_FOUND;
      atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atchops_rsa_decrypt: %d; error:AT0015-key not found\n", ret);
      goto exit;
    }
  }

  char *response_without_data = response + 5; // skip "data:"
  const size_t response_without_data_len = strlen(response_without_data);

  /*
   * 6. Decrypt and return it
   */
  if ((ret = atchops_base64_decode((unsigned char *)response_without_data, response_without_data_len, key_raw_encrypted,
                                   key_raw_encrypted_size, &key_raw_encrypted_len)) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atchops_base64_decode: %d\n", ret);
    goto exit;
  }

  if ((ret = atchops_rsa_decrypt(ctx->atkeys.encryptprivatekey, key_raw_encrypted, key_raw_encrypted_len,
                                 key_raw_decrypted, key_raw_decrypted_size, &key_raw_decrypted_len)) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atchops_rsa_decrypt: %d\n", ret);
    goto exit;
  }

  if ((ret = atchops_base64_decode((unsigned char *)key_raw_decrypted, key_raw_decrypted_len,
                                   shared_encryption_key_shared_by_me, ATCHOPS_AES_256 / 8, NULL)) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atchops_base64_decode: %d\n", ret);
    goto exit;
  }

exit: {
  free(command);
  free(sender_atsign_with_at);
  free(recipient_atsign_with_at);
  return ret;
}
}

int atclient_get_shared_encryption_key_shared_by_other(atclient *ctx, const char *recipient_atsign,
                                                       unsigned char *shared_encryption_key_shared_by_other) {
  int ret = 1;

  /*
   * 1. Validate arguments
   */
  if (ctx == NULL) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "ctx is NULL\n");
    return ret;
  }

  if (recipient_atsign == NULL) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "recipient_atsign is NULL\n");
    return ret;
  }

  if (shared_encryption_key_shared_by_other == NULL) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "shared_encryption_key_shared_by_other is NULL\n");
    return ret;
  }

  /*
   * 2. Variables
   */
  char *sender_atsign_with_at = NULL;
  char *recipient_atsign_with_at = NULL;
  char *command = NULL;

  const size_t recvsize = 1024;
  unsigned char recv[recvsize];

  const size_t shared_encryption_key_encrypted_base64_size = 1024;
  unsigned char shared_encryption_key_encrypted_base64[shared_encryption_key_encrypted_base64_size];

  const size_t shared_encryption_key_encrypted_size = 1024;
  unsigned char shared_encryption_key_encrypted[shared_encryption_key_encrypted_size];

  /*
   * 3. Build lookup: command
   */
  if ((ret = atclient_stringutils_atsign_with_at(ctx->atsign, &sender_atsign_with_at)) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atclient_stringutils_atsign_with_at: %d\n", ret);
    goto exit;
  }

  if ((ret = atclient_stringutils_atsign_with_at(recipient_atsign, &recipient_atsign_with_at)) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atclient_stringutils_atsign_with_at: %d\n", ret);
    goto exit;
  }

  short commandsize = strlen("lookup:shared_key") + strlen(recipient_atsign_with_at) + strlen("\r\n") + 1;
  if ((command = (char *)malloc(sizeof(char) * commandsize)) == NULL) {
    ret = 1;
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "Failed to allocate memory for command\n");
    goto exit;
  }
  snprintf(command, commandsize, "lookup:shared_key%s\r\n", recipient_atsign_with_at);

  /*
   * 4. Send command to atserver
   */
  memset(recv, 0, sizeof(unsigned char) * recvsize);
  size_t recvlen = 0;

  if ((ret = atclient_connection_send(&(ctx->atserver_connection), (unsigned char *)command, strlen((char *)command),
                                      recv, recvsize, &recvlen)) != 0) {
    return ret;
  }

  /*
   * 5. Parse response
   */
  char *response = (char *)recv;
  char *response_without_data = response + 5; // skip "data:"

  if (!atclient_stringutils_starts_with(response, "data:")) {
    if (atclient_stringutils_starts_with(response, "error:AT0015-key not found")) {
      ret = ATCLIENT_ERR_AT0015_KEY_NOT_FOUND;
      atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "key not found\n", ret);
      return ret;
    }
  }
  memset(shared_encryption_key_encrypted_base64, 0,
         sizeof(unsigned char) * shared_encryption_key_encrypted_base64_size);
  size_t shared_encryption_key_encrypted_base64_len = 0;

  if ((ret = atchops_base64_decode((unsigned char *)response_without_data, strlen(response_without_data),
                                   shared_encryption_key_encrypted_base64, shared_encryption_key_encrypted_base64_size,
                                   &shared_encryption_key_encrypted_base64_len)) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atchops_base64_decode: %d\n", ret);
    return ret;
  }

  memset(shared_encryption_key_encrypted, 0, sizeof(unsigned char) * shared_encryption_key_encrypted_size);
  size_t shared_encryption_key_encrypted_len = 0;

  if ((ret = atchops_rsa_decrypt(ctx->atkeys.encryptprivatekey, shared_encryption_key_encrypted_base64,
                                 shared_encryption_key_encrypted_base64_len, shared_encryption_key_encrypted,
                                 shared_encryption_key_encrypted_size, &shared_encryption_key_encrypted_len)) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atchops_rsa_decrypt: %d\n", ret);
    return ret;
  }

  const size_t shared_encryption_key_shared_by_other_size = ATCHOPS_AES_256 / 8;
  if ((ret = atchops_base64_decode(shared_encryption_key_encrypted, shared_encryption_key_encrypted_len,
                                   shared_encryption_key_shared_by_other, shared_encryption_key_shared_by_other_size,
                                   NULL)) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atchops_base64_decode: %d\n", ret);
    return ret;
  }

exit: {
  free(command);
  free(sender_atsign_with_at);
  free(recipient_atsign_with_at);
  return ret;
}
}

int atclient_create_shared_encryption_key_pair_for_me_and_other(
    atclient *atclient, const char *sharedby, const char *sharedwith,
    unsigned char *shared_encryption_key_shared_by_me_with_other) {

  int ret = 1;

  /*
   * 1. Validate arguments
   */
  if (atclient == NULL) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atclient is NULL\n");
    return ret;
  }

  if (sharedby == NULL) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "sharedby is NULL\n");
    return ret;
  }

  if (sharedwith == NULL) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "sharedwith is NULL\n");
    return ret;
  }

  if (shared_encryption_key_shared_by_me_with_other == NULL) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "shared_encryption_key_shared_by_me_with_other is NULL\n");
    return ret;
  }

  /*
   * 2. Variables
   */

  // holds formatted atSigns
  char *sharedby_atsign_with_at = NULL;
  char *sharedwith_atsign_with_at = NULL;

  // holds their public key in base64 format, non-encrypted
  char *publickeybase64 = NULL;

  // holds their public key in base64 format, non-encrypted (struct)
  atchops_rsakey_publickey publickeystruct;
  atchops_rsakey_publickey_init(&publickeystruct);

  // the original AES-256 key
  const size_t shared_encryption_key_size = ATCHOPS_AES_256 / 8;
  unsigned char shared_encryption_key[shared_encryption_key_size];

  // the original AES-256 key (base64 encoded)
  const size_t shared_encryption_key_base64_size = atchops_base64_encoded_size(shared_encryption_key_size);
  unsigned char shared_encryption_key_base64[shared_encryption_key_base64_size];

  // encrypted for us
  const size_t shared_encryption_key_base64_encrypted_for_us_size = 512;
  unsigned char shared_encryption_key_base64_encrypted_for_us[shared_encryption_key_base64_encrypted_for_us_size];

  // encrypted for us (base64 encoded)
  const size_t shared_encryption_key_base64_encrypted_for_us_base64_size =
      atchops_base64_encoded_size(shared_encryption_key_base64_encrypted_for_us_size);
  unsigned char
      shared_encryption_key_base64_encrypted_for_us_base64[shared_encryption_key_base64_encrypted_for_us_base64_size];

  // encrypted for them
  const size_t shared_encryption_key_base64_encrypted_for_them_size = 512;
  unsigned char shared_encryption_key_base64_encrypted_for_them[shared_encryption_key_base64_encrypted_for_them_size];

  // encrypted for them (base64 encoded)
  const size_t shared_encryption_key_base64_encrypted_for_them_base64_size =
      atchops_base64_encoded_size(shared_encryption_key_base64_encrypted_for_them_size);
  unsigned char shared_encryption_key_base64_encrypted_for_them_base64
      [shared_encryption_key_base64_encrypted_for_them_base64_size];

  char *cmdbuffer1 = NULL; // for us (update:shared_key.sharedwith@sharedby command)
  char *cmdbuffer2 = NULL; // for them (update:@sharedwith:shared_key@sharedby command)

  const size_t recvsize = 256; // sufficient to receive response from a update: command
  unsigned char recv[recvsize];
  memset(recv, 0, sizeof(unsigned char) * recvsize);
  size_t recvlen = 0;

  /*
   * 2. Ensure atSigns start with `@` symbol
   */
  if ((ret = atclient_stringutils_atsign_with_at(sharedby, &sharedby_atsign_with_at)) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atclient_stringutils_atsign_with_at: %d\n", ret);
    goto exit;
  }
  char *sharedby_atsign_without_at = sharedby_atsign_with_at + 1;

  if ((ret = atclient_stringutils_atsign_with_at(sharedwith, &sharedwith_atsign_with_at)) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atclient_stringutils_atsign_with_at: %d\n", ret);
    goto exit;
  }
  char *sharedwith_atsign_without_at = sharedwith_atsign_with_at + 1;

  /*
   * 3. Get publickey of sharedwith atSign
   */
  if ((ret = atclient_get_public_encryption_key(atclient, sharedwith_atsign_with_at, &publickeybase64)) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atclient_get_public_encryption_key: %d\n", ret);
    goto exit;
  }

  if ((ret = atchops_rsakey_populate_publickey(&publickeystruct, publickeybase64, strlen(publickeybase64))) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atchops_rsakey_populate_publickey: %d\n", ret);
    goto exit;
  }

  /*
   * 4. Generate 32-byte AES key
   */
  memset(shared_encryption_key, 0, sizeof(unsigned char) * shared_encryption_key_size);
  if ((ret = atchops_aes_generate_key(shared_encryption_key, ATCHOPS_AES_256)) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atchops_aes_generate_key: %d\n", ret);
    goto exit;
  }

  memset(shared_encryption_key_base64, 0, sizeof(char) * shared_encryption_key_base64_size);
  size_t shared_encryption_key_base64_len = 0;
  if ((ret = atchops_base64_encode(shared_encryption_key, shared_encryption_key_size, shared_encryption_key_base64,
                                   shared_encryption_key_base64_size, &shared_encryption_key_base64_len)) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atchops_base64_encode: %d\n", ret);
    goto exit;
  }

  /*
   * 5. Do encryption stuff
   *   a. Encrypt for us
   *   b. Encrypt for them
   */

  // 5a. Encrypt for us
  size_t shared_encryption_key_base64_encrypted_for_us_len = 0;
  memset(shared_encryption_key_base64_encrypted_for_us, 0,
         sizeof(unsigned char) * shared_encryption_key_base64_encrypted_for_us_size);
  if ((ret = atchops_rsa_encrypt(atclient->atkeys.encryptpublickey, (unsigned char *)shared_encryption_key_base64,
                                 shared_encryption_key_base64_len, shared_encryption_key_base64_encrypted_for_us,
                                 shared_encryption_key_base64_encrypted_for_us_size,
                                 &shared_encryption_key_base64_encrypted_for_us_len)) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR,
                 "failed to encrypt shared enc key for us | atchops_rsa_encrypt: %d\n", ret);
    goto exit;
  }

  size_t shared_encryption_key_base64_encrypted_for_us_base64_len = 0;
  memset(shared_encryption_key_base64_encrypted_for_us_base64, 0,
         sizeof(unsigned char) * shared_encryption_key_base64_encrypted_for_us_base64_size);
  if ((ret = atchops_base64_encode(shared_encryption_key_base64_encrypted_for_us,
                                   shared_encryption_key_base64_encrypted_for_us_len,
                                   shared_encryption_key_base64_encrypted_for_us_base64,
                                   shared_encryption_key_base64_encrypted_for_us_base64_size,
                                   &shared_encryption_key_base64_encrypted_for_us_base64_len)) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR,
                 "failed to base64 encode shared enc key for us | atchops_base64_encode: %d\n", ret);
    goto exit;
  }

  // 5b. Encrypt for them
  size_t shared_encryption_key_base64_encrypted_for_them_len = 0;
  memset(shared_encryption_key_base64_encrypted_for_them, 0,
         sizeof(unsigned char) * shared_encryption_key_base64_encrypted_for_them_size);
  if ((ret = atchops_rsa_encrypt(publickeystruct, shared_encryption_key_base64, shared_encryption_key_base64_len,
                                 shared_encryption_key_base64_encrypted_for_them,
                                 shared_encryption_key_base64_encrypted_for_them_size,
                                 &shared_encryption_key_base64_encrypted_for_them_len)) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atchops_rsa_encrypt: %d\n", ret);
    goto exit;
  }

  size_t shared_encryption_key_base64_encrypted_for_them_base64_len = 0;
  memset(shared_encryption_key_base64_encrypted_for_them_base64, 0,
         sizeof(unsigned char) * shared_encryption_key_base64_encrypted_for_them_base64_size);
  if ((ret = atchops_base64_encode(shared_encryption_key_base64_encrypted_for_them,
                                   shared_encryption_key_base64_encrypted_for_them_len,
                                   shared_encryption_key_base64_encrypted_for_them_base64,
                                   shared_encryption_key_base64_encrypted_for_them_base64_size,
                                   &shared_encryption_key_base64_encrypted_for_them_base64_len)) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atchops_base64_encode: %d\n", ret);
    goto exit;
  }

  /*
   * 6. Build `update:` commands
   */
  // 6a. `update:shared_key.recipient_atsign@myatsign <key>`
  const size_t cmdbuffersize1 = strlen("update:shared_key.") + strlen(sharedwith_atsign_without_at) +
                                strlen(sharedby_atsign_with_at) + strlen(" ") +
                                shared_encryption_key_base64_encrypted_for_us_base64_len + strlen("\r\n") + 1;
  if ((cmdbuffer1 = (char *)malloc(sizeof(char) * cmdbuffersize1)) == NULL) {
    ret = 1;
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "Failed to allocate memory for cmdbuffer1\n");
    goto exit;
  }
  snprintf(cmdbuffer1, cmdbuffersize1, "update:shared_key.%s%s %s\r\n", sharedwith_atsign_without_at,
           sharedby_atsign_with_at, shared_encryption_key_base64_encrypted_for_us_base64);

  // 6b. `update:@sharedwith:shared_key@sharedby <key>`
  const size_t cmdbuffersize2 = strlen("update:") + strlen(sharedwith_atsign_with_at) + strlen(":shared_key") +
                                strlen(sharedby_atsign_with_at) + strlen(" ") +
                                shared_encryption_key_base64_encrypted_for_them_base64_len + strlen("\r\n") + 1;

  if ((cmdbuffer2 = (char *)malloc(sizeof(char) * cmdbuffersize2)) == NULL) {
    ret = 1;
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "Failed to allocate memory for cmdbuffer2\n");
    goto exit;
  }
  snprintf(cmdbuffer2, cmdbuffersize2, "update:%s:shared_key%s %s\r\n", sharedwith_atsign_with_at,
           sharedby_atsign_with_at, shared_encryption_key_base64_encrypted_for_them_base64);

  /*
   * 7. Send commands to atserver
   */

  // 7a. Our key
  if ((ret = atclient_connection_send(&(atclient->atserver_connection), (unsigned char *)cmdbuffer1, cmdbuffersize1 - 1,
                                      recv, recvsize, &recvlen)) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atclient_connection_send: %d\n", ret);
    goto exit;
  }

  if (!atclient_stringutils_starts_with((char *)recv, "data:")) {
    ret = 1;
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "recv was \"%.*s\" and did not have prefix \"data:\"\n",
                 (int)recvlen, recv);
    goto exit;
  }

  memset(recv, 0, sizeof(unsigned char) * recvsize);
  recvlen = 0;

  // 7b. Their key
  if ((ret = atclient_connection_send(&(atclient->atserver_connection), (unsigned char *)cmdbuffer2, cmdbuffersize2 - 1,
                                      recv, recvsize, &recvlen)) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atclient_connection_send: %d\n", ret);
    goto exit;
  }

  if (!atclient_stringutils_starts_with((char *)recv, "data:")) {
    ret = 1;
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "recv was \"%.*s\" and did not have prefix \"data:\"\n",
                 (int)recvlen, recv);
    goto exit;
  }

  /*
   * 8. Return output
   */
  memcpy(shared_encryption_key_shared_by_me_with_other, shared_encryption_key, shared_encryption_key_size);

  ret = 0;
  goto exit;
exit: {
  free(sharedby_atsign_with_at);
  free(sharedwith_atsign_with_at);
  atchops_rsakey_publickey_free(&publickeystruct);
  free(publickeybase64);
  free(cmdbuffer1);
  free(cmdbuffer2);
  return ret;
}
}
