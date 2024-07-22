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

int atclient_get_shared_encryption_key_shared_by_me(atclient *ctx, const char *recipient_atsign,
                                                    char *enc_key_shared_by_me, bool create_new_if_not_found) {
  int ret = 1;

  char *sender_atsign_with_at = NULL;
  char *sender_atsign_without_at = NULL;

  char *recipient_atsign_with_at = NULL;
  char *recipient_atsign_without_at = NULL;

  if ((ret = atclient_stringutils_atsign_with_at(ctx->atsign, &sender_atsign_with_at)) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atclient_stringutils_atsign_with_at: %d\n", ret);
    return ret;
  }

  if ((ret = atclient_stringutils_atsign_without_at(sender_atsign_with_at, &sender_atsign_without_at)) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atclient_stringutils_atsign_without_at: %d\n", ret);
    return ret;
  }

  if ((ret = atclient_stringutils_atsign_with_at(recipient_atsign, &recipient_atsign_with_at)) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atclient_stringutils_atsign_with_at: %d\n", ret);
    return ret;
  }

  if ((ret = atclient_stringutils_atsign_without_at(recipient_atsign_with_at, &recipient_atsign_without_at)) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atclient_stringutils_atsign_without_at: %d\n", ret);
    return ret;
  }

  // llookup:shared_key.recipient_atsign@myatsign
  const short commandsize =
      strlen("llookup:shared_key.") + strlen(recipient_atsign_without_at) + strlen(sender_atsign_with_at) + strlen("\r\n") + 1;
  char command[commandsize];
  memset(command, 0, sizeof(char) * commandsize);
  snprintf(command, commandsize, "llookup:shared_key.%s%s\r\n", recipient_atsign_without_at, sender_atsign_with_at);

  const size_t recvsize = 1024;
  unsigned char recv[recvsize];
  memset(recv, 0, sizeof(unsigned char) * recvsize);
  size_t recvlen = 0;

  ret = atclient_connection_send(&(ctx->atserver_connection), (unsigned char *)command, commandsize - 1, recv, recvsize,
                                 &recvlen);
  if (ret != 0) {
    return ret;
  }

  char *response = (char *)recv;

  // Truncate response: "@" + myatsign + "@"
  const short responseprefixsize = strlen(sender_atsign_with_at) + 3;
  char responseprefix[responseprefixsize];
  memset(responseprefix, 0, sizeof(char) * responseprefixsize);
  snprintf(responseprefix, responseprefixsize, "@%s@", sender_atsign_without_at);
  const short responseprefixlen = (short)strlen(response);

  if (atclient_stringutils_starts_with(response, responseprefix)) {
    response = response + responseprefixlen;
  }
  short responselen = (short)strlen(response);

  if (atclient_stringutils_ends_with(response, responseprefix)) {
    response[responselen - responseprefixlen - 1] = '\0';
  }

  // does my atSign already have the recipient's shared key?
  if (atclient_stringutils_starts_with(response, "data:")) {
    response = response + 5;
    responselen = (short)strlen(response);

    // 44 + 1
    const size_t plaintextsize = 45;
    unsigned char plaintext[plaintextsize];
    memset(plaintext, 0, sizeof(unsigned char) * plaintextsize);
    size_t plaintextlen = 0;

    const size_t responserawsize = 512;
    unsigned char responseraw[responserawsize];
    memset(responseraw, 0, sizeof(unsigned char) * responserawsize);
    size_t responserawlen = 0;

    ret = atchops_base64_decode((unsigned char *)response, responselen, responseraw, responserawsize, &responserawlen);
    if (ret != 0) {
      atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atchops_base64_decode: %d\n", ret);
      return ret;
    }

    ret = atchops_rsa_decrypt(ctx->atkeys.encryptprivatekey, responseraw, responserawlen, plaintext, plaintextsize,
                              &plaintextlen);
    if (ret != 0) {
      atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atchops_rsa_decrypt: %d\n", ret);
      return ret;
    }

    memcpy(enc_key_shared_by_me, plaintext, plaintextsize);
  }

  else if (atclient_stringutils_starts_with((char *)recv, "error:AT0015-key not found")) {
    // or do I need to create, store and share a new shared key?
    if (create_new_if_not_found) {
      atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_INFO, "Creating new shared encryption key for %s\n",
                   recipient_atsign_with_at);
      ret = atclient_create_shared_encryption_key_pair_for_me_and_other(ctx, sender_atsign_with_at,
                                                                        recipient_atsign_with_at, enc_key_shared_by_me);
      if (ret != 0) {
        atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atclient_create_shared_encryption_key: %d\n", ret);
        return ret;
      }
    } else {
      ret = ATCLIENT_ERR_AT0015_KEY_NOT_FOUND;
      return ret;
    }
  }

  return 0;
}

int atclient_get_shared_encryption_key_shared_by_other(atclient *ctx, const char *recipient_atsign,
                                                       char *enc_key_shared_by_other) {
  int ret = 1;

  char *sender_atsign_with_at = NULL;
  char *sender_atsign_without_at = NULL;

  char *recipient_atsign_with_at = NULL;
  char *recipient_atsign_without_at = NULL;

  if ((ret = atclient_stringutils_atsign_with_at(ctx->atsign, &sender_atsign_with_at)) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atclient_stringutils_atsign_with_at: %d\n", ret);
    return ret;
  }

  if ((ret = atclient_stringutils_atsign_without_at(sender_atsign_with_at, &sender_atsign_without_at)) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atclient_stringutils_atsign_without_at: %d\n", ret);
    return ret;
  }

  if ((ret = atclient_stringutils_atsign_with_at(recipient_atsign, &recipient_atsign_with_at)) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atclient_stringutils_atsign_with_at: %d\n", ret);
    return ret;
  }

  if ((ret = atclient_stringutils_atsign_without_at(recipient_atsign_with_at, &recipient_atsign_without_at)) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atclient_stringutils_atsign_without_at: %d\n", ret);
    return ret;
  }

  // llookup:cached:@myatsign:shared_key@recipient_atsign
  // lookup:shared_key@recipient_atsign
  char *command_prefix = "lookup:shared_key@";
  const short command_prefix_len = 18;

  short commandsize = command_prefix_len + strlen(recipient_atsign_without_at) + 3;
  char command[commandsize];
  snprintf(command, commandsize, "lookup:shared_key@%s\r\n", recipient_atsign_without_at);

  const size_t recvsize = 1024;
  unsigned char recv[recvsize];
  memset(recv, 0, sizeof(unsigned char) * recvsize);
  size_t recvlen = 0;

  ret = atclient_connection_send(&(ctx->atserver_connection), (unsigned char *)command, strlen((char *)command), recv,
                                 recvsize, &recvlen);
  if (ret != 0) {
    return ret;
  }

  char *response = (char *)recv;

  // Truncate response: "@" + myatsign + "@"
  short response_prefix_len = (short)strlen(sender_atsign_without_at) + 3;
  char response_prefix[response_prefix_len];
  snprintf(response_prefix, response_prefix_len, "@%s@", sender_atsign_without_at);

  if (atclient_stringutils_starts_with(response, response_prefix)) {
    response = response + response_prefix_len;
  }

  if (atclient_stringutils_ends_with(response, response_prefix)) {
    response[strlen(response) - response_prefix_len - 1] = '\0';
  }

  // does my atSign already have the recipient's shared key?
  if (atclient_stringutils_starts_with(response, "data:")) {

    response = response + 5;

    // 44 + 1
    const size_t plaintextlen = 45;
    unsigned char plaintext[plaintextlen];
    memset(plaintext, 0, plaintextlen);
    size_t plaintextolen = 0;

    const size_t responserawsize = 1024;
    unsigned char responseraw[responserawsize];
    memset(responseraw, 0, sizeof(unsigned char) * responserawsize);
    size_t responserawlen = 0;

    ret = atchops_base64_decode((unsigned char *)response, strlen(response), responseraw, responserawsize,
                                &responserawlen);
    if (ret != 0) {
      atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atchops_base64_decode: %d\n", ret);
      return ret;
    }

    ret = atchops_rsa_decrypt(ctx->atkeys.encryptprivatekey, responseraw, responserawlen, plaintext, plaintextlen,
                              &plaintextolen);
    if (ret != 0) {
      atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atchops_rsa_decrypt: %d\n", ret);
      return ret;
    }

    memcpy(enc_key_shared_by_other, plaintext, plaintextlen);
  } else if (atclient_stringutils_starts_with((char *)recv, "error:AT0015-key not found")) {
    // There is nothing we can do, except wait for the recipient to share a new key
    // We want to mark this situation with a easily distinguishable return value
    ret = ATCLIENT_ERR_AT0015_KEY_NOT_FOUND;
    return ret;
  }

  return 0;
}

int atclient_get_public_encryption_key(atclient *ctx, const char *atsign, char *public_encryption_key) {

  int ret = 1;

  bool should_free_atsign_with_at = false;
  char *atsign_with_at = ctx->atsign;

  if (atsign != NULL) {
    if ((ret = atclient_stringutils_atsign_with_at(atsign, &atsign_with_at)) != 0) {
      atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atclient_stringutils_atsign_with_at: %d\n", ret);
      return ret;
    }
    should_free_atsign_with_at = true;
  }

  // plookup:publickey@atsign
  char *command_prefix = "plookup:publickey";
  const short command_prefix_len = 17;

  short command_len = command_prefix_len + strlen(atsign_with_at) + 3;
  char command[command_len];
  snprintf(command, command_len, "plookup:publickey%s\r\n", atsign_with_at);

  // execute command
  const size_t recvlen = 1024;
  unsigned char recv[recvlen];
  memset(recv, 0, sizeof(unsigned char) * recvlen);
  size_t olen = 0;

  ret = atclient_connection_send(&(ctx->atserver_connection), (unsigned char *)command, strlen((char *)command), recv,
                                 recvlen, &olen);
  if (ret != 0) {
    return ret;
  }

  char *response = (char *)recv;

  if (atclient_stringutils_starts_with(response, "data:")) {
    response = response + 5;
    memcpy(public_encryption_key, response, 1024);
  } else if (atclient_stringutils_starts_with((char *)recv, "error:AT0015-key not found")) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atchops_rsa_decrypt: %d; error:AT0015-key not found\n", ret);
    ret = 1;
    return ret;
  }

  ret = 0;
exit: {
  if (should_free_atsign_with_at) {
    free(atsign_with_at);
  }
  return ret;
}
}

int atclient_create_shared_encryption_key_pair_for_me_and_other(atclient *atclient, const char *sharedby,
                                                                const char *sharedwith, char *sharedenckeybyme) {
  int ret = 1;

  // 1. variables
  // holds unencrypted shared encryption key in base 64 format
  const size_t sharedenckeybase64size = 64;
  unsigned char sharedenckeybase64[sharedenckeybase64size];
  memset(sharedenckeybase64, 0, sizeof(unsigned char) * sharedenckeybase64size);
  size_t sharedenckeybase64len = 0;

  // encrypted for us
  const size_t sharedenckeyencryptedforussize = 512;
  unsigned char sharedenckeyencryptedforus[sharedenckeyencryptedforussize];
  memset(sharedenckeyencryptedforus, 0, sizeof(unsigned char) * sharedenckeyencryptedforussize);
  size_t sharedenckeyencryptedforuslen = 0;

  const size_t sharedenckeybase64encryptedforussize = 512;
  char sharedenckeybase64encryptedforus[sharedenckeybase64encryptedforussize];
  memset(sharedenckeybase64encryptedforus, 0, sizeof(char) * sharedenckeybase64encryptedforussize);
  size_t sharedenckeybase64encryptedforuslen = 0;

  // encrypted for them
  const size_t sharedenckeyencryptedforthemsize = 512;
  unsigned char sharedenckeyencryptedforthem[sharedenckeyencryptedforthemsize];
  memset(sharedenckeyencryptedforthem, 0, sizeof(unsigned char) * sharedenckeyencryptedforthemsize);
  size_t sharedenckeyencryptedforthemlen = 0;

  const size_t sharedenckeybase64encryptedforthemsize = 512;
  char sharedenckeybase64encryptedforthem[sharedenckeybase64encryptedforthemsize];
  memset(sharedenckeybase64encryptedforthem, 0, sizeof(char) * sharedenckeybase64encryptedforthemsize);
  size_t sharedenckeybase64encryptedforthemlen = 0;

  // their public encyrption key
  const size_t publickeybase64size = 1024;
  char publickeybase64[publickeybase64size];
  memset(publickeybase64, 0, sizeof(char) * publickeybase64size);

  const size_t recvsize = 2048;
  unsigned char recv[recvsize];
  memset(recv, 0, sizeof(unsigned char) * recvsize);
  size_t recvlen = 0;

  char *cmdbuffer1 = NULL;
  char *cmdbuffer2 = NULL;

  char *sharedby_atsign_with_at = NULL;
  char *sharedby_atsign_without_at = NULL;

  char *sharedwith_atsign_with_at = NULL;
  char *sharedwith_atsign_without_at = NULL;

  atchops_rsakey_publickey publickeystruct;
  atchops_rsakey_publickey_init(&publickeystruct);

  if ((ret = atclient_stringutils_atsign_with_at(sharedby, &sharedby_atsign_with_at)) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atclient_stringutils_atsign_with_at: %d\n", ret);
    return ret;
  }

  if ((ret = atclient_stringutils_atsign_without_at(sharedby_atsign_with_at, &sharedby_atsign_without_at)) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atclient_stringutils_atsign_without_at: %d\n", ret);
    return ret;
  }

  if ((ret = atclient_stringutils_atsign_with_at(sharedwith, &sharedwith_atsign_with_at)) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atclient_stringutils_atsign_with_at: %d\n", ret);
    return ret;
  }

  if ((ret = atclient_stringutils_atsign_without_at(sharedwith_atsign_with_at, &sharedwith_atsign_without_at)) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atclient_stringutils_atsign_without_at: %d\n", ret);
    return ret;
  }

  // 2. generate shared encryption key
  ret = atchops_aes_generate_keybase64(sharedenckeybase64, sharedenckeybase64size, &sharedenckeybase64len,
                                       ATCHOPS_AES_256);
  if (ret != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atchops_aes_generate_keybase64: %d\n", ret);
    return ret;
  }

  // 3. encrypt for us (with encrypt public key)
  ret =
      atchops_rsa_encrypt(atclient->atkeys.encryptpublickey, (unsigned char *)sharedenckeybase64, sharedenckeybase64len,
                          sharedenckeyencryptedforus, sharedenckeyencryptedforussize, &sharedenckeyencryptedforuslen);
  if (ret != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR,
                 "failed to encrypt shared enc key for us | atchops_rsa_encrypt: %d\n", ret);
    return ret;
  }

  ret = atchops_base64_encode(sharedenckeyencryptedforus, sharedenckeyencryptedforuslen,
                              (unsigned char *)sharedenckeybase64encryptedforus, sharedenckeybase64encryptedforussize,
                              &sharedenckeybase64encryptedforuslen);
  if (ret != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR,
                 "failed to base64 encode shared enc key for us | atchops_base64_encode: %d\n", ret);
    return ret;
  }

  // 4. encrypt for them (with their rsa public encryption key)
  ret = atclient_get_public_encryption_key(atclient, sharedwith, publickeybase64);
  if (ret != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atclient_get_public_encryption_key: %d\n", ret);
    return ret;
  }

  // create a rsakey public (atchops)
  ret = atchops_rsakey_populate_publickey(&publickeystruct, publickeybase64, strlen(publickeybase64));
  if (ret != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atchops_rsakey_populate_publickey: %d\n", ret);
    return ret;
  }

  // encrypt the symmetric key with their rsa public key
  ret = atchops_rsa_encrypt(publickeystruct, (unsigned char *)sharedenckeybase64, sharedenckeybase64len,
                            sharedenckeyencryptedforthem, sharedenckeyencryptedforthemsize,
                            &sharedenckeyencryptedforthemlen);
  if (ret != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atchops_rsa_encrypt: %d\n", ret);
    return ret;
  }

  ret = atchops_base64_encode(sharedenckeyencryptedforthem, sharedenckeyencryptedforthemlen,
                              (unsigned char *)sharedenckeybase64encryptedforthem,
                              sharedenckeybase64encryptedforthemsize, &sharedenckeybase64encryptedforthemlen);
  if (ret != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR,
                 "failed to base64 encode shared enc key for them | atchops_base64_encode: %d\n", ret);
    goto exit;
  }

  // 5. prep protocol commands
  // 5a. for us (update:shared_key.sharedby@sharedwith <encrypted for us>\r\n)
  const size_t cmdbuffersize1 = strlen("update:shared_key. \r\n") + strlen(sharedwith_atsign_without_at) +
                                strlen(sharedby_atsign_with_at) + 1 + sharedenckeybase64encryptedforuslen;
  cmdbuffer1 = (char *)malloc(sizeof(char) * cmdbuffersize1);
  if (cmdbuffer1 == NULL) {
    ret = 1;
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "Failed to allocate memory for cmdbuffer1\n");
    goto exit;
  }
  snprintf(cmdbuffer1, cmdbuffersize1, "update:shared_key.%s%s %s\r\n", sharedwith_atsign_without_at,
           sharedby_atsign_with_at, sharedenckeybase64encryptedforus);

  // 5b. for them (update:shared_key.sharedwith@sharedby <encrypted for them>\r\n)
  const size_t cmdbuffersize2 = strlen("update::shared_key \r\n") + strlen(sharedby_atsign_with_at) +
                                strlen(sharedwith_atsign_with_at) + 1 + sharedenckeybase64encryptedforthemlen;
  if ((cmdbuffer2 = (char *)malloc(sizeof(char) * cmdbuffersize2)) == NULL) {
    ret = 1;
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "Failed to allocate memory for cmdbuffer2\n");
    goto exit;
  }
  snprintf(cmdbuffer2, cmdbuffersize2, "update:%s:shared_key%s %s\r\n", sharedwith_atsign_with_at,
           sharedby_atsign_with_at, sharedenckeybase64encryptedforthem);

  // 6. put "encrypted for us" into key store
  ret = atclient_connection_send(&(atclient->atserver_connection), (unsigned char *)cmdbuffer1, cmdbuffersize1 - 1,
                                 recv, recvsize, &recvlen);
  if (ret != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atclient_connection_send: %d\n", ret);
    goto exit;
  }

  // check if the key was successfully stored
  if (!atclient_stringutils_starts_with((char *)recv, "data:")) {
    ret = 1;
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "recv was \"%.*s\" and did not have prefix \"data:\"\n",
                 (int)recvlen, recv);
    goto exit;
  }

  memset(recv, 0, sizeof(unsigned char) * recvsize);

  // 6. put "encrypted for them" into key store
  ret = atclient_connection_send(&(atclient->atserver_connection), (unsigned char *)cmdbuffer2, cmdbuffersize2 - 1,
                                 recv, recvsize, &recvlen);
  if (ret != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atclient_connection_send: %d\n", ret);
    goto exit;
  }

  // check if the key was successfully stored
  if (!atclient_stringutils_starts_with((char *)recv, "data:")) {
    ret = 1;
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "recv was \"%.*s\" and did not have prefix \"data:\"\n",
                 (int)recvlen, recv);
    goto exit;
  }

  // 7. return shared encryption key by me
  memcpy(sharedenckeybyme, sharedenckeybase64, sharedenckeybase64len);

  ret = 0;
  goto exit;

exit: {
  atchops_rsakey_publickey_free(&publickeystruct);
  free(cmdbuffer1);
  free(cmdbuffer2);
  free(sharedby_atsign_with_at);
  free(sharedby_atsign_without_at);
  free(sharedwith_atsign_with_at);
  free(sharedwith_atsign_without_at);
  return ret;
}
}
