#include "atclient/encryption_key_helpers.h"
#include "atclient/atclient.h"
#include "atclient/atkey.h"
#include "atclient/atkeys.h"
#include "atclient/atsign.h"
#include "atclient/stringutils.h"
#include <atchops/aes.h>
#include <atchops/base64.h>
#include <atlogger/atlogger.h>
#include <stdlib.h>
#include <string.h>

#define TAG "encryption_key_helpers"

int atclient_get_shared_encryption_key_shared_by_me(atclient *ctx, const char *sharedwith, const size_t sharedwithlen,
                                                    unsigned char *sharedenckey) {
  int ret = 1;

  const size_t sharedwith_withatsize = sharedwithlen + 1;
  char sharedwith_withat[sharedwith_withatsize];
  memset(sharedwith_withat, 0, sizeof(char) * sharedwith_withatsize);
  size_t sharedwith_withatlen = 0;

  if ((ret = atclient_atsign_with_at_symbol(sharedwith_withat, sharedwith_withatsize, &sharedwith_withatlen, sharedwith,
                                            sharedwithlen)) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atclient_atsign_with_at_symbol: %d\n", ret);
    return ret;
  }

  // llookup:shared_key.recipient_atsign@myatsign
  const size_t commandsize =
      strlen("llookup:shared_key.") + (sharedwith_withatlen - 1) + strlen(ctx->atsign.atsign) + strlen("\r\n") + 1;
  char command[commandsize];
  memset(command, 0, sizeof(char) * commandsize);
  snprintf(command, commandsize, "llookup:shared_key.%.*s%s\r\n", (int)sharedwith_withatlen, sharedwith_withat + 1,
           ctx->atsign.atsign);

  const size_t recvsize = 1024;
  unsigned char recv[recvsize];
  memset(recv, 0, sizeof(unsigned char) * recvsize);
  size_t recvlen = 0;

  ret = atclient_connection_send(&(ctx->secondary_connection), (unsigned char *)command, commandsize - 1, recv,
                                 recvsize, &recvlen);
  if (ret != 0) {
    return ret;
  }

  if (atclient_stringutils_starts_with((const char *)recv, recvlen, "data:", strlen("data:"))) {
    const char *response = recv + 5;
    const short responselen = (short)strlen(response);

    const size_t responserawsize = 512;
    unsigned char responseraw[responserawsize];
    memset(responseraw, 0, sizeof(unsigned char) * responserawsize);
    size_t responserawlen = 0;

    ret = atchops_base64_decode((unsigned char *)response, responselen, responseraw, responserawsize, &responserawlen);
    if (ret != 0) {
      atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atchops_base64_decode: %d\n", ret);
      return ret;
    }

    const size_t sharedenckeybase64size = 45;
    unsigned char sharedenckeybase64[sharedenckeybase64size];
    memset(sharedenckeybase64, 0, sizeof(unsigned char) * sharedenckeybase64size);
    size_t sharedenckeybase64len = 0;

    ret = atchops_rsa_decrypt(ctx->atkeys.encryptprivatekey, responseraw, responserawlen, sharedenckeybase64,
                              sharedenckeybase64size, &sharedenckeybase64len);
    if (ret != 0) {
      atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atchops_rsa_decrypt: %d\n", ret);
      return ret;
    }

    const size_t sharedenckeytempsize = 32;
    unsigned char sharedenckeytemp[sharedenckeytempsize];
    memset(sharedenckeytemp, 0, sizeof(unsigned char) * sharedenckeytempsize);
    size_t sharedenckeylen = 0;

    ret = atchops_base64_decode(sharedenckeybase64, sharedenckeybase64len, sharedenckeytemp, sharedenckeytempsize,
                                &(sharedenckeylen));
    if (ret != 0) {
      atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atchops_base64_decode: %d\n", ret);
      return ret;
    }

    if (sharedenckeylen != 32) {
      atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "sharedenckeylen is not 32\n");
      return 1;
    }

    memcpy(sharedenckey, sharedenckeytemp, sharedenckeylen);
  }

  else if (atclient_stringutils_starts_with((const char *)recv, recvlen, "error:AT0015-key not found",
                                            strlen("error:AT0015-key not found"))) {
    return ATCLIENT_ERR_AT0015_KEY_NOT_FOUND;
  }

  return -1;
}

int atclient_get_shared_encryption_key_shared_by_other(atclient *ctx, const char *sharedby, const size_t sharedbylen,
                                                       unsigned char *sharedenckey) {
  int ret = 1;

  const size_t sharedby_withatsize = sharedbylen + 1;
  char sharedby_withat[sharedby_withatsize];
  memset(sharedby_withat, 0, sizeof(char) * sharedby_withatsize);
  size_t sharedby_withatlen = 0;

  if ((ret = atclient_atsign_with_at_symbol(sharedby_withat, sharedby_withatsize, &sharedby_withatlen, sharedby,
                                            sharedbylen)) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atclient_atsign_with_at_symbol: %d\n", ret);
    return ret;
  }

  short commandsize = strlen("lookup:shared_key") + sharedby_withatlen + strlen("\r\n") + 1;
  char command[commandsize];
  memset(command, 0, sizeof(char) * commandsize);
  snprintf(command, commandsize, "lookup:shared_key%.*s\r\n", (int)sharedby_withatlen, sharedby_withat);

  const size_t recvsize = 1024;
  unsigned char recv[recvsize];
  memset(recv, 0, sizeof(unsigned char) * recvsize);
  size_t recvlen = 0;

  ret = atclient_connection_send(&(ctx->secondary_connection), (unsigned char *)command, strlen((char *)command), recv,
                                 recvsize, &recvlen);
  if (ret != 0) {
    return ret;
  }

  if (atclient_stringutils_starts_with((const char *)recv, recvlen, "data:", strlen("data:"))) {
    char *response = recv + strlen("data:");
    size_t responselen = recvlen - strlen("data:");

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

    const size_t sharedenckeybase64size = 45;
    unsigned char sharedenckeybase64[sharedenckeybase64size];
    memset(sharedenckeybase64, 0, sharedenckeybase64size);
    size_t sharedenckeybase64len = 0;

    ret = atchops_rsa_decrypt(ctx->atkeys.encryptprivatekey, responseraw, responserawlen, sharedenckeybase64,
                              sharedenckeybase64size, &sharedenckeybase64len);
    if (ret != 0) {
      atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atchops_rsa_decrypt: %d\n", ret);
      return ret;
    }

    const size_t sharedenckeytempsize = 32;
    unsigned char sharedenckeytemp[sharedenckeytempsize];
    memset(sharedenckeytemp, 0, sharedenckeytempsize);
    size_t sharedenckeylen = 0;

    ret = atchops_base64_decode(sharedenckeybase64, sharedenckeybase64len, sharedenckeytemp, sharedenckeytempsize,
                                &(sharedenckeylen));
    if (ret != 0) {
      atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atchops_base64_decode: %d\n", ret);
      return ret;
    }

    if (sharedenckeylen != 32) {
      atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "sharedenckeylen is not 32\n");
      return 1;
    }

    memcpy(sharedenckey, sharedenckeytemp, sharedenckeylen);

  } else if (atclient_stringutils_starts_with((const char *)recv, recvlen, "error:AT0015-key not found",
                                              strlen("error:AT0015-key not found"))) {
    ret = ATCLIENT_ERR_AT0015_KEY_NOT_FOUND;
    return ret;
  }

  return 0;
}

int atclient_get_public_encryption_key(atclient *ctx, const char *atsign, const size_t atsignlen,
                                       char *publicenckeybase64, const size_t publicenckeybase64size,
                                       size_t *publicenckeybase64len) {

  int ret = 1;

  if (publicenckeybase64 == NULL) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "sharedenckeybyme is NULL\n");
    return ret;
  }

  const size_t atsign_withatsize = strlen(atsign) + 1;
  char atsign_withat[atsign_withatsize];
  memset(atsign_withat, 0, sizeof(char) * atsign_withatsize);
  size_t atsign_withatlen = 0;

  if ((ret = atclient_atsign_with_at_symbol(atsign_withat, atsign_withatsize, &atsign_withatlen, atsign,
                                            strlen(atsign))) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atclient_atsign_with_at_symbol: %d\n", ret);
    return ret;
  }

  const short commandsize = strlen("plookup:publickey") + atsign_withatlen + strlen("\r\n") + 1;
  char command[commandsize];
  memset(command, 0, sizeof(char) * commandsize);
  snprintf(command, commandsize, "plookup:publickey%.*s\r\n", (int)atsign_withatlen, atsign_withat);

  const size_t recvsize = 1024;
  unsigned char recv[recvsize];
  memset(recv, 0, sizeof(unsigned char) * recvsize);
  size_t recvlen = 0;

  if ((ret = atclient_connection_send(&(ctx->secondary_connection), (const unsigned char *)command, strlen(command),
                                      recv, recvsize, &recvlen)) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atclient_connection_send: %d\n", ret);
    return ret;
  }

  if (recvlen == 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "recvlen is 0\n");
    return 1;
  }

  if (atclient_stringutils_starts_with((const char *)recv, recvlen, "data:", strlen("data:"))) {
    const char *response = recv + strlen("data:");
    const size_t responselen = recvlen - strlen("data:");

    if (responselen > publicenckeybase64size) {
      atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "publicenckeybase64size is too small\n");
      return 1;
    }

    if (publicenckeybase64 == NULL) {
      atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "publicenckeybase64 is NULL\n");
      return 1;
    }

    memcpy(publicenckeybase64, response, responselen);

    if (publicenckeybase64len != NULL) {
      *publicenckeybase64len = responselen;
    }
    ret = 0;
  } else if (atclient_stringutils_starts_with((const char *)recv, recvlen, "error:AT0015-key not found",
                                              strlen("error:AT0015-key not found"))) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "recv began with error:AT0015-key not found\n");
    ret = ATCLIENT_ERR_AT0015_KEY_NOT_FOUND;
    return ret;
  }

  return ret;
}

int atclient_create_shared_encryption_keypair_for_me_and_other(atclient *atclient, const char *sharedwith,
                                                               const size_t sharedwithlen,
                                                               unsigned char *sharedenckey) {
  int ret = 1;

  if (sharedenckey == NULL) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR,
                 "sharedenckeybyme is NULL, this should be a pointer to a buffer with 32 bytes of allocated size\n");
    return ret;
  }

  // 1. variables

  // unencrypted shared encryption key
  const size_t sharedenckeytempsize = ATCHOPS_AES_256 / 8;
  unsigned char sharedenckeytemp[sharedenckeytempsize];
  memset(sharedenckeytemp, 0, sizeof(unsigned char) * sharedenckeytempsize);
  size_t sharedenckeytemplen = 0;

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
  const size_t publickeybase64size = 512;
  char publickeybase64[publickeybase64size];
  memset(publickeybase64, 0, sizeof(char) * publickeybase64size);
  size_t publickeybase64len = 0;

  const size_t sharedwith_withatsize = sharedwithlen + 1;
  char sharedwith_withat[sharedwith_withatsize];
  memset(sharedwith_withat, 0, sizeof(char) * sharedwith_withatsize);
  size_t sharedwith_withatlen = 0;

  const size_t recvsize = 2048;
  unsigned char recv[recvsize];
  memset(recv, 0, sizeof(unsigned char) * recvsize);
  size_t recvlen = 0;

  atchops_rsakey_publickey publickeystruct;
  atchops_rsakey_publickey_init(&publickeystruct);

  char *cmdbuffer1 = NULL;
  char *cmdbuffer2 = NULL;

  if ((ret = atclient_atsign_with_at_symbol(sharedwith_withat, sharedwith_withatsize, &sharedwith_withatlen, sharedwith,
                                            sharedwithlen)) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atclient_atsign_with_at_symbol: %d\n", ret);
    goto exit;
  }

  // 2. generate shared encryption key
  ret = atchops_aes_generate_key(sharedenckeytemp, ATCHOPS_AES_256);
  if (ret != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atchops_aes_generate_keybase64: %d\n", ret);
    goto exit;
  }
  sharedenckeytemplen = 32;

  ret = atchops_base64_encode(sharedenckeytemp, sharedenckeytemplen, sharedenckeybase64, sharedenckeybase64size,
                              &sharedenckeybase64len);
  if (ret != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR,
                 "failed to base64 encode shared enc key | atchops_base64_encode: %d\n", ret);
    goto exit;
  }

  // 3. encrypt for us (with self encryption key)
  ret =
      atchops_rsa_encrypt(atclient->atkeys.encryptpublickey, (unsigned char *)sharedenckeybase64, sharedenckeybase64len,
                          sharedenckeyencryptedforus, sharedenckeyencryptedforussize, &sharedenckeyencryptedforuslen);
  if (ret != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR,
                 "failed to encrypt shared enc key for us | atchops_rsa_encrypt: %d\n", ret);
    goto exit;
  }

  ret = atchops_base64_encode(sharedenckeyencryptedforus, sharedenckeyencryptedforuslen,
                              (unsigned char *)sharedenckeybase64encryptedforus, sharedenckeybase64encryptedforussize,
                              &sharedenckeybase64encryptedforuslen);
  if (ret != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR,
                 "failed to base64 encode shared enc key for us | atchops_base64_encode: %d\n", ret);
    goto exit;
  }

  // 4. encrypt for them (with their rsa public encryption key)
  ret = atclient_get_public_encryption_key(atclient, sharedwith_withat, sharedwith_withatlen, publickeybase64,
                                           publickeybase64size, &publickeybase64len);
  if (ret != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atclient_get_public_encryption_key: %d\n", ret);
    goto exit;
  }

  // create a rsakey public (atchops)
  ret = atchops_rsakey_populate_publickey(&publickeystruct, publickeybase64, publickeybase64len);
  if (ret != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atchops_rsakey_populate_publickey: %d\n", ret);
    return ret;
  }

  // encrypt the base 64 symmetric key with their rsa public key
  ret = atchops_rsa_encrypt(publickeystruct, (unsigned char *)sharedenckeybase64, sharedenckeybase64len,
                            sharedenckeyencryptedforthem, sharedenckeyencryptedforthemsize,
                            &sharedenckeyencryptedforthemlen);
  if (ret != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atchops_rsa_encrypt: %d\n", ret);
    return ret;
  }

  // base64 encode the cipher text bytes
  ret = atchops_base64_encode(sharedenckeyencryptedforthem, sharedenckeyencryptedforthemlen,
                              (unsigned char *)sharedenckeybase64encryptedforthem,
                              sharedenckeybase64encryptedforthemsize, &sharedenckeybase64encryptedforthemlen);
  if (ret != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR,
                 "failed to base64 encode shared enc key for them | atchops_base64_encode: %d\n", ret);
    return ret;
  }

  // 5. prep protocol commands

  // 5a. for us (update:shared_key.sharedwith@sharedby <encrypted for us>\r\n)
  const size_t cmdbuffersize1 = strlen("update:shared_key. \r\n") + (sharedwith_withatlen - 1) +
                                strlen(atclient->atsign.atsign) + sharedenckeybase64encryptedforuslen + 1;
  cmdbuffer1 = malloc(sizeof(char) * cmdbuffersize1);
  memset(cmdbuffer1, 0, sizeof(char) * cmdbuffersize1);
  snprintf(cmdbuffer1, cmdbuffersize1, "update:shared_key.%s%s %s\r\n", (sharedwith_withat + 1),
           atclient->atsign.atsign, sharedenckeybase64encryptedforus);

  // 5b. for them (update:@sharedwith:shared_key@sharedby <encrypted for them>\r\n)
  const size_t cmdbuffersize2 = strlen("update::shared_key \r\n") + sharedwith_withatlen +
                                strlen(atclient->atsign.atsign) + sharedenckeybase64encryptedforthemlen + 1;
  cmdbuffer2 = malloc(sizeof(char) * cmdbuffersize2);
  memset(cmdbuffer2, 0, sizeof(char) * cmdbuffersize2);
  snprintf(cmdbuffer2, cmdbuffersize2, "update:%s:shared_key%s %s\r\n", sharedwith_withat, atclient->atsign.atsign,
           sharedenckeybase64encryptedforthem);

  // 6. execute protocol commands

  // 6a. put "encrypted for us" into key store
  ret = atclient_connection_send(&(atclient->secondary_connection), (unsigned char *)cmdbuffer1, cmdbuffersize1 - 1,
                                 recv, recvsize, &recvlen);
  if (ret != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atclient_connection_send: %d\n", ret);
    return ret;
  }

  // check if the key was successfully stored
  if (!atclient_stringutils_starts_with((const char *)recv, recvlen, "data:", strlen("data:"))) {
    ret = 1;
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "recv was \"%.*s\" and did not have prefix \"data:\"\n",
                 (int)recvlen, recv);
    return ret;
  }

  memset(recv, 0, sizeof(unsigned char) * recvsize);

  // 6b. put "encrypted for them" into key store
  ret = atclient_connection_send(&(atclient->secondary_connection), (unsigned char *)cmdbuffer2, cmdbuffersize2 - 1,
                                 recv, recvsize, &recvlen);
  if (ret != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atclient_connection_send: %d\n", ret);
    return ret;
  }

  // check if the key was successfully stored
  if (!atclient_stringutils_starts_with((const char *)recv, recvlen, "data:", strlen("data:"))) {
    ret = 1;
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "recv was \"%.*s\" and did not have prefix \"data:\"\n",
                 (int)recvlen, recv);
    goto exit;
  }

  // 7. return shared encryption key by me
  memcpy(sharedenckey, sharedenckeybase64, sharedenckeybase64len);

  ret = 0;
  goto exit;

exit: {
  free(cmdbuffer1);
  free(cmdbuffer2);
  atchops_rsakey_publickey_free(&publickeystruct);
  return ret;
}
}
