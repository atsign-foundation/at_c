#include "atclient/encryption_key_helpers.h"
#include "atchops/aes.h"
#include "atchops/base64.h"
#include "atclient/atclient.h"
#include "atclient/atkeys.h"
#include "atclient/stringutils.h"
#include "atlogger/atlogger.h"
#include <stdlib.h>
#include <string.h>

#define TAG "encryption_key_helpers"
#define ATCLIENT_ERR_AT0015_KEY_NOT_FOUND -0x1980

int atclient_get_shared_encryption_key_shared_by_me(atclient *ctx, const atclient_atsign *recipient,
                                                    char *enc_key_shared_by_me, bool create_new_if_not_found) {
  int ret = 1;

  // llookup:shared_key.recipient_atsign@myatsign
  const short commandsize = strlen("llookup:shared_key.") + strlen(recipient->without_prefix_str) +
                            strlen(ctx->atsign.atsign) + strlen("\r\n") + 1;
  char command[commandsize];
  memset(command, 0, sizeof(char) * commandsize);
  snprintf(command, commandsize, "llookup:shared_key.%s%s\r\n", recipient->without_prefix_str, ctx->atsign.atsign);

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
  const short responseprefixsize = strlen(ctx->atsign.atsign) + 3;
  char responseprefix[responseprefixsize];
  memset(responseprefix, 0, sizeof(char) * responseprefixsize);
  snprintf(responseprefix, responseprefixsize, "@%s@", ctx->atsign.without_prefix_str);
  const short responseprefixlen = (short)strlen(response);

  if (atclient_stringutils_starts_with(response, responseprefixlen, responseprefix, responseprefixlen)) {
    response = response + responseprefixlen;
  }
  short responselen = (short)strlen(response);

  if (atclient_stringutils_ends_with(response, responselen, responseprefix, responseprefixlen)) {
    response[responselen - responseprefixlen - 1] = '\0';
  }

  // does my atSign already have the recipient's shared key?
  if (atclient_stringutils_starts_with(response, responselen, "data:", 5)) {
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

  else if (atclient_stringutils_starts_with((char *)recv, recvsize, "error:AT0015-key not found",
                                            strlen("error:AT0015-key not found"))) {
    // or do I need to create, store and share a new shared key?
    if (create_new_if_not_found) {
      atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_INFO, "Creating new shared encryption key for %s\n", recipient->atsign);
      ret = atclient_create_shared_encryption_key_pair_for_me_and_other(ctx, &(ctx->atsign), recipient,
                                                                        enc_key_shared_by_me);
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

int atclient_get_shared_encryption_key_shared_by_other(atclient *ctx, const atclient_atsign *recipient,
                                                       char *enc_key_shared_by_other) {
  int ret = 1;

  // llookup:cached:@myatsign:shared_key@recipient_atsign
  // lookup:shared_key@recipient_atsign
  char *command_prefix = "lookup:shared_key@";
  const short command_prefix_len = 18;

  short commandsize = command_prefix_len + strlen(recipient->without_prefix_str) + 3;
  char command[commandsize];
  snprintf(command, commandsize, "lookup:shared_key@%s\r\n", recipient->without_prefix_str);

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
  short response_prefix_len = (short)strlen(ctx->atsign.without_prefix_str) + 3;
  char response_prefix[response_prefix_len];
  snprintf(response_prefix, response_prefix_len, "@%s@", ctx->atsign.without_prefix_str);

  if (atclient_stringutils_starts_with(response, recvsize, response_prefix, response_prefix_len)) {
    response = response + response_prefix_len;
  }

  if (atclient_stringutils_ends_with(response, recvsize, response_prefix, response_prefix_len)) {
    response[strlen(response) - response_prefix_len - 1] = '\0';
  }

  // does my atSign already have the recipient's shared key?
  if (atclient_stringutils_starts_with(response, recvsize, "data:", 5)) {

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
  } else if (atclient_stringutils_starts_with((char *)recv, recvsize, "error:AT0015-key not found",
                                              strlen("error:AT0015-key not found"))) {
    // There is nothing we can do, except wait for the recipient to share a new key
    // We want to mark this situation with a easily distinguishable return value
    ret = ATCLIENT_ERR_AT0015_KEY_NOT_FOUND;
    return ret;
  }

  return 0;
}

int atclient_get_public_encryption_key(atclient *ctx, const atclient_atsign *atsign, char *public_encryption_key) {

  int ret = 1;

  // plookup:publickey@atsign
  char *command_prefix = "plookup:publickey";
  const short command_prefix_len = 17;

  const atclient_atsign *pub_enc_key_atsign = atsign != NULL ? atsign : &ctx->atsign;
  short command_len = command_prefix_len + strlen(pub_enc_key_atsign->atsign) + 3;
  char command[command_len];
  snprintf(command, command_len, "plookup:publickey%s\r\n", pub_enc_key_atsign->atsign);

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

  if (atclient_stringutils_starts_with(response, recvlen, "data:", 5)) {
    response = response + 5;
    memcpy(public_encryption_key, response, 1024);
  } else if (atclient_stringutils_starts_with((char *)recv, recvlen, "error:AT0015-key not found",
                                              strlen("error:AT0015-key not found"))) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atchops_rsa_decrypt: %d; error:AT0015-key not found\n", ret);
    ret = 1;
    return ret;
  }

  return 0;
}

int atclient_create_shared_encryption_key_pair_for_me_and_other(atclient *atclient, const atclient_atsign *sharedby,
                                                                const atclient_atsign *sharedwith,
                                                                char *sharedenckeybyme) {
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

  atchops_rsakey_publickey publickeystruct;
  atchops_rsakey_publickey_init(&publickeystruct);

  // 2. generate shared encryption key
  ret = atchops_aes_generate_keybase64(sharedenckeybase64, sharedenckeybase64size, &sharedenckeybase64len,
                                       ATCHOPS_AES_256);
  if (ret != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atchops_aes_generate_keybase64: %d\n", ret);
    return ret;
  }

  // 3. encrypt for us (with self encryption key)
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
  const size_t cmdbuffersize1 = strlen("update:shared_key. \r\n") + strlen(sharedwith->without_prefix_str) +
                                strlen(sharedby->atsign) + 1 + sharedenckeybase64encryptedforuslen;
  cmdbuffer1 = (char *)malloc(sizeof(char) * cmdbuffersize1);
  snprintf(cmdbuffer1, cmdbuffersize1, "update:shared_key.%s%s %s\r\n", sharedwith->without_prefix_str,
           sharedby->atsign, sharedenckeybase64encryptedforus);

  // 5b. for them (update:shared_key.sharedwith@sharedby <encrypted for them>\r\n)
  const size_t cmdbuffersize2 = strlen("update::shared_key \r\n") + strlen(sharedby->atsign) +
                                strlen(sharedwith->atsign) + 1 + sharedenckeybase64encryptedforthemlen;
  cmdbuffer2 = (char *)malloc(sizeof(char) * cmdbuffersize2);
  snprintf(cmdbuffer2, cmdbuffersize2, "update:%s:shared_key%s %s\r\n", sharedwith->atsign, sharedby->atsign,
           sharedenckeybase64encryptedforthem);

  // 6. put "encrypted for us" into key store
  ret = atclient_connection_send(&(atclient->atserver_connection), (unsigned char *)cmdbuffer1, cmdbuffersize1 - 1,
                                 recv, recvsize, &recvlen);
  if (ret != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atclient_connection_send: %d\n", ret);
    goto exit;
  }

  // check if the key was successfully stored
  if (!atclient_stringutils_starts_with((char *)recv, recvlen, "data:", 5)) {
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
  if (!atclient_stringutils_starts_with((char *)recv, recvlen, "data:", 5)) {
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
  return ret;
}
}
