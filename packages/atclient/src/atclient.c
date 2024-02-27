#include "atclient/atclient.h"
#include "atchops/aes.h"
#include "atchops/rsa.h"
#include "atclient/atbytes.h"
#include "atclient/atkey.h"
#include "atclient/atkeys.h"
#include "atclient/atsign.h"
#include "atclient/atstr.h"
#include "atclient/connection.h"
#include "atclient/stringutils.h"
#include "atlogger/atlogger.h"
#include <cJSON/cJSON.h>
#include <mbedtls/md.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define HOST_BUFFER_SIZE 1024 // the size of the buffer for the host name for root and secondary

#define ATCLIENT_ERR_AT0015_KEY_NOT_FOUND -0x1980

#define TAG "atclient"

void atclient_init(atclient *ctx) { memset(ctx, 0, sizeof(atclient)); }

int atclient_start_root_connection(atclient *ctx, const char *roothost, const int rootport) {
  int ret = 1; // error by default

  atclient_connection_init(&(ctx->root_connection));

  ret = atclient_connection_connect(&(ctx->root_connection), roothost, rootport);
  if (ret != 0) {
    atclient_atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atclient_connection_connect: %d\n", ret);
    goto exit;
  }
  atclient_atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_INFO,
                        "atclient_connection_connect: %d. Successfully connected to root\n", ret);

  goto exit;

exit: { return ret; }
}

int atclient_start_secondary_connection(atclient *ctx, const char *secondaryhost, const int secondaryport) {
  int ret = 1; // error by default

  atclient_connection_init(&(ctx->secondary_connection));
  ret = atclient_connection_connect(&(ctx->secondary_connection), secondaryhost, secondaryport);
  if (ret != 0) {
    atclient_atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atclient_connection_connect: %d\n", ret);
    goto exit;
  }
  atclient_atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_INFO,
                        "atclient_connection_connect: %d. Successfully connected to secondary\n", ret);

  goto exit;

exit: { return ret; }
}

int atclient_pkam_authenticate(atclient *ctx, const atclient_atkeys atkeys, const char *atsign,
                               const unsigned long atsignlen) {
  int ret = 1; // error by default

  // 1. init root connection
  const unsigned long srclen = 1024;
  atclient_atbytes src;
  atclient_atbytes_init(&src, srclen);

  const unsigned long recvlen = 1024;
  atclient_atbytes recv;
  atclient_atbytes_init(&recv, recvlen);

  const unsigned long withoutatlen = 1024;
  atclient_atstr withoutat;
  atclient_atstr_init(&withoutat, withoutatlen);

  const unsigned long urllen = 256;
  atclient_atstr url;
  atclient_atstr_init(&url, 256);

  atclient_atstr host;
  atclient_atstr_init(&host, 256);
  int port = 0;

  const unsigned long atsigncmdlen = 1024;
  atclient_atstr atsigncmd;
  atclient_atstr_init(&atsigncmd, atsigncmdlen);

  const unsigned long fromcmdlen = 1024;
  atclient_atstr fromcmd;
  atclient_atstr_init(&fromcmd, fromcmdlen);

  const unsigned long challengelen = 1024;
  atclient_atstr challenge;
  atclient_atstr_init(&challenge, challengelen);

  const unsigned long challengewithoutdatalen = 1024;
  atclient_atstr challengewithoutdata;
  atclient_atstr_init(&challengewithoutdata, challengewithoutdatalen);

  const unsigned long challengebyteslen = 1024;
  atclient_atbytes challengebytes;
  atclient_atbytes_init(&challengebytes, challengebyteslen);

  const unsigned long pkamcmdlen = 1024;
  atclient_atstr pkamcmd;
  atclient_atstr_init(&pkamcmd, pkamcmdlen);

  ret = atclient_atsign_without_at_symbol(withoutat.str, withoutat.len, &(withoutat.olen), atsign, atsignlen);
  if (ret != 0) {
    atclient_atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atclient_atsign_without_at_symbol: %d\n", ret);
    goto exit;
  }

  ret = atclient_atstr_set_literal(&atsigncmd, "%.*s\r\n", (int)withoutat.olen, withoutat.str);
  if (ret != 0) {
    atclient_atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atclient_atstr_set_literal: %d\n", ret);
    goto exit;
  }

  ret = atclient_atbytes_convert_atstr(&src, atsigncmd);
  if (ret != 0) {
    atclient_atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atclient_atbytes_convert_atstr: %d\n", ret);
    goto exit;
  }

  ret = atclient_connection_send(&(ctx->root_connection), src.bytes, src.olen, recv.bytes, recv.len, &(recv.olen));
  if (ret != 0) {
    atclient_atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atclient_connection_send: %d\n | failed to send: %.*s\n",
                          ret, withoutat.olen, withoutat);
    goto exit;
  }

  // 2. init secondary connection
  // recv is something like 3b419d7a-2fee-5080-9289-f0e1853abb47.swarm0002.atsign.zone:5770
  // store host and port in separate vars
  ret = atclient_atstr_set_literal(&url, "%.*s", (int)recv.olen, recv.bytes);
  if (ret != 0) {
    atclient_atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atclient_atstr_set_literal: %d\n", ret);
    goto exit;
  }

  ret = atclient_connection_get_host_and_port(&host, &port, url);
  if (ret != 0) {
    atclient_atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR,
                          "atclient_connection_get_host_and_port: %d | failed to parse url %.*s\n", ret, recv.olen,
                          recv.bytes);
    goto exit;
  }

  ret = atclient_start_secondary_connection(ctx, host.str, port);
  if (ret != 0) {
    atclient_atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atclient_start_secondary_connection: %d\n", ret);
    goto exit;
  }

  // 3. send pkam auth
  ret = atclient_atstr_set_literal(&fromcmd, "from:%.*s\r\n", (int)withoutat.olen, withoutat.str);
  if (ret != 0) {
    atclient_atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atclient_atstr_set_literal: %d\n", ret);
    goto exit;
  }

  ret = atclient_atbytes_convert(&src, fromcmd.str, fromcmd.olen);
  if (ret != 0) {
    atclient_atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atclient_atbytes_convert: %d\n", ret);
    goto exit;
  }

  ret = atclient_connection_send(&(ctx->secondary_connection), src.bytes, src.olen, recv.bytes, recv.len, &(recv.olen));
  if (ret != 0) {
    atclient_atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atclient_connection_send: %d\n", ret);
    goto exit;
  }

  ret = atclient_atstr_set_literal(&challenge, "%.*s", (int)recv.olen, recv.bytes);
  if (ret != 0) {
    atclient_atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atclient_atstr_set_literal: %d\n", ret);
    goto exit;
  }

  // remove "data:" prefix
  ret = atclient_atstr_substring(&challengewithoutdata, challenge, 5, challenge.olen);
  if (ret != 0) {
    atclient_atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR,
                          "atclient_atstr_substring: %d\n | failed to remove \'data:\' prefix", ret);
    goto exit;
  }

  // sign
  atclient_atbytes_reset(&recv);
  ret = atclient_atbytes_convert_atstr(&challengebytes, challengewithoutdata);
  if (ret != 0) {
    atclient_atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atclient_atbytes_convert_atstr: %d\n", ret);
    goto exit;
  }
  ret = atchops_rsa_sign(atkeys.pkamprivatekey, MBEDTLS_MD_SHA256, challengebytes.bytes, challengebytes.olen,
                         recv.bytes, recv.len, &recv.olen);
  if (ret != 0) {
    atclient_atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atchops_rsa_sign: %d\n", ret);
    goto exit;
  }

  ret = atclient_atstr_set_literal(&pkamcmd, "pkam:%.*s\r\n", (int)recv.olen, recv.bytes);
  if (ret != 0) {
    atclient_atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atclient_atstr_set_literal: %d\n", ret);
    goto exit;
  }

  atclient_atbytes_reset(&recv);
  ret = atclient_atbytes_convert_atstr(&src, pkamcmd);
  if (ret != 0) {
    atclient_atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atclient_atbytes_convert_atstr: %d\n", ret);
    goto exit;
  }

  ret = atclient_connection_send(&(ctx->secondary_connection), src.bytes, src.olen, recv.bytes, recv.len, &recv.olen);
  if (ret != 0) {
    atclient_atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atclient_connection_send: %d\n", ret);
    goto exit;
  }

  // check for data:success
  if (!atclient_stringutils_starts_with((char *)recv.bytes, recv.olen, "data:success", strlen("data:success"))) {
    ret = 1;
    atclient_atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR,
                          "recv was \"%.*s\" and did not have prefix \"data:success\"\n", (int)recv.olen, recv.bytes);
    goto exit;
  }

  ret = 0;

  goto exit;
exit: {
  atclient_atbytes_free(&src);
  atclient_atbytes_free(&recv);
  atclient_atstr_free(&withoutat);
  atclient_atstr_free(&url);
  atclient_atstr_free(&host);
  atclient_atstr_free(&atsigncmd);
  atclient_atstr_free(&fromcmd);
  atclient_atstr_free(&challenge);
  atclient_atstr_free(&challengewithoutdata);
  atclient_atbytes_free(&challengebytes);
  atclient_atstr_free(&pkamcmd);
  return ret;
}
}

int atclient_put(atclient *atclient, const atclient_atkey *atkey, const char *value, const size_t valuelen) {
  int ret = 1;

  goto exit;
exit: { return ret; }
}

int atclient_get_selfkey(atclient *atclient, atclient_atkey *atkey, char *value, const size_t valuelen,
                         size_t *valueolen) {
  int ret = 1;

  // TODO: implement

  goto exit;
exit: { return ret; }
}

int atclient_get_publickey(atclient *atclient, const atclient_atkey *atkey, char *value, const size_t valuelen,
                           size_t *valueolen) {
  int ret = 1;

  // TODO: implement

  ret = 0;
  goto exit;
exit: { return ret; }
}

int atclient_get_sharedkey(atclient *atclient, const atclient_atkey *atkey, char *value, const size_t valuelen,
                           size_t *valueolen) {
  int ret = 1;

  // TODO: implement

  goto exit;
exit: { return ret; }
}

int atclient_delete(atclient *atclient, const atclient_atkey *atkey) {
  int ret = 1;

  atclient_atstr cmdbuffer;
  atclient_atstr_init_literal(&cmdbuffer, ATKEY_GENERAL_BUFFER_SIZE + strlen("delete:"), "delete:");

  char atkeystr[ATKEY_GENERAL_BUFFER_SIZE];
  memset(atkeystr, 0, sizeof(char) * ATKEY_GENERAL_BUFFER_SIZE);
  size_t atkeystrolen = 0;

  unsigned char recv[4096] = {0};
  size_t recvolen = 0;

  ret = atclient_atkey_to_string(*atkey, atkeystr, ATKEY_GENERAL_BUFFER_SIZE, &atkeystrolen);
  if (ret != 0) {
    atclient_atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atclient_atkey_to_string: %d\n", ret);
    goto exit;
  }

  ret = atclient_atstr_append(&cmdbuffer, "%.*s\n", (int)atkeystrolen, atkeystr);
  if (ret != 0) {
    atclient_atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atclient_atstr_append: %d\n", ret);
    goto exit;
  }

  ret = atclient_connection_send(&(atclient->secondary_connection), (unsigned char *)cmdbuffer.str, cmdbuffer.olen,
                                 recv, 4096, &recvolen);
  if (ret != 0) {
    atclient_atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atclient_connection_send: %d\n", ret);
    goto exit;
  }

  if (!atclient_stringutils_starts_with((char *)recv, recvolen, "data:", 5)) {
    ret = 1;
    atclient_atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "recv was \"%.*s\" and did not have prefix \"data:\"\n",
                          (int)recvolen, recv);
    goto exit;
  }

  ret = 0;
  goto exit;
exit: {
  atclient_atstr_free(&cmdbuffer);
  return ret;
}
}

int atclient_get_encryption_key_shared_by_me(atclient *ctx, const atclient_atsign *recipient,
                                             char *enc_key_shared_by_me, bool create_new_if_not_found) {
  int ret = 1;

  // llookup:shared_key.recipient_atsign@myatsign
  char *command_prefix = "llookup:shared_key.";
  const short command_prefix_len = 19;
  short atsign_with_at_len = (short)strlen(ctx->atsign.atsign);

  short command_len = command_prefix_len + (short)strlen(recipient->without_prefix_str) + atsign_with_at_len + 3;
  char command[command_len];
  snprintf(command, command_len, "llookup:shared_key.%s%s\r\n", recipient->without_prefix_str, ctx->atsign.atsign);

  const size_t recvlen = 1024;
  unsigned char recv[recvlen];
  memset(recv, 0, sizeof(unsigned char) * recvlen);
  size_t olen = 0;

  ret = atclient_connection_send(&(ctx->secondary_connection), (unsigned char *)command, strlen((char *)command), recv,
                                 recvlen, &olen);
  if (ret != 0) {
    return ret;
  }

  char *response = (char *)recv;

  // Truncate response: "@" + myatsign + "@"
  int response_prefix_len = atsign_with_at_len + 2;
  char response_prefix[response_prefix_len];
  snprintf(response_prefix, response_prefix_len, "@%s@", ctx->atsign.without_prefix_str);

  if (atclient_stringutils_starts_with(response, recvlen, response_prefix, response_prefix_len)) {
    response = response + response_prefix_len;
  }

  if (atclient_stringutils_ends_with(response, recvlen, response_prefix, response_prefix_len)) {
    response[strlen(response) - response_prefix_len - 1] = '\0';
  }

  // does my atSign already have the recipient's shared key?
  if (atclient_stringutils_starts_with(response, recvlen, "data:", 5)) {
    response = response + 5;

    // 44 + 1
    const size_t plaintextlen = 45;
    unsigned char plaintext[plaintextlen];
    memset(plaintext, 0, plaintextlen);
    size_t plaintextolen = 0;

    ret = atchops_rsa_decrypt(ctx->atkeys.encryptprivatekey, (const unsigned char *)response, strlen((char *)response),
                              plaintext, plaintextlen, &plaintextolen);
    if (ret != 0) {
      atclient_atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atchops_rsa_decrypt: %d\n", ret);
      return ret;
    }

    memcpy(enc_key_shared_by_me, plaintext, plaintextlen);
  }

  else if (atclient_stringutils_starts_with((char *)recv, recvlen, "error:AT0015-key not found",
                                            strlen("error:AT0015-key not found"))) {
    // or do I need to create, store and share a new shared key?
    if (create_new_if_not_found) {
      ret = atclient_create_shared_encryption_key(ctx, recipient, enc_key_shared_by_me);
      if (ret != 0) {
        atclient_atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atclient_create_shared_encryption_key: %d\n", ret);
        return ret;
      }
    } else {
      ret = ATCLIENT_ERR_AT0015_KEY_NOT_FOUND;
      return ret;
    }
  }

  return 0;
}

int atclient_get_encryption_key_shared_by_other(atclient *ctx, const atclient_atsign *recipient,
                                                char *enc_key_shared_by_other) {
  int ret = 1;

  // llookup:cached:@myatsign:shared_key@recipient_atsign
  // lookup:shared_key@recipient_atsign
  char *command_prefix = "lookup:shared_key@";
  const short command_prefix_len = 18;

  short command_len = command_prefix_len + strlen(recipient->without_prefix_str) + 3;
  char command[command_len];
  snprintf(command, command_len, "lookup:shared_key@%s\r\n", recipient->without_prefix_str);

  const size_t recvlen = 1024;
  unsigned char recv[recvlen];
  memset(recv, 0, sizeof(unsigned char) * recvlen);
  size_t olen = 0;

  ret = atclient_connection_send(&(ctx->secondary_connection), (unsigned char *)command, strlen((char *)command), recv,
                                 recvlen, &olen);
  if (ret != 0) {
    return ret;
  }

  char *response = (char *)recv;

  // Truncate response: "@" + myatsign + "@"
  short response_prefix_len = (short)strlen(ctx->atsign.without_prefix_str) + 3;
  char response_prefix[response_prefix_len];
  snprintf(response_prefix, response_prefix_len, "@%s@", ctx->atsign.without_prefix_str);

  if (atclient_stringutils_starts_with(response, recvlen, response_prefix, response_prefix_len)) {
    response = response + response_prefix_len;
  }

  if (atclient_stringutils_ends_with(response, recvlen, response_prefix, response_prefix_len)) {
    response[strlen(response) - response_prefix_len - 1] = '\0';
  }

  // does my atSign already have the recipient's shared key?
  if (atclient_stringutils_starts_with(response, recvlen, "data:", 5)) {

    response = response + 5;

    // 44 + 1
    const size_t plaintextlen = 45;
    unsigned char plaintext[plaintextlen];
    memset(plaintext, 0, plaintextlen);
    size_t plaintextolen = 0;

    ret = atchops_rsa_decrypt(ctx->atkeys.encryptprivatekey, (const unsigned char *)response, strlen((char *)response),
                              plaintext, plaintextlen, &plaintextolen);
    if (ret != 0) {
      atclient_atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atchops_rsa_decrypt: %d\n", ret);
      return ret;
    }
    memcpy(enc_key_shared_by_other, plaintext, plaintextlen);
  } else if (atclient_stringutils_starts_with((char *)recv, recvlen, "error:AT0015-key not found",
                                              strlen("error:AT0015-key not found"))) {
    // There is nothing we can do, except wait for the recipient to share a new key
    // We want to mark this situation with a easily distinguishable return value
    ret = ATCLIENT_ERR_AT0015_KEY_NOT_FOUND;
    return ret;
  }
  return 0;
}

int atclient_create_shared_encryption_key(atclient *ctx, const atclient_atsign *recipient, char *enc_key_shared_by_me) {
  int ret = 1;

  // get client and recipient public encryption keys
  const size_t bufferlen = 1024;
  char client_public_encryption_key[bufferlen];
  char recipient_public_encryption_key[bufferlen];
  ret = atclient_get_public_encryption_key(ctx, NULL, client_public_encryption_key);
  if (ret != 0) {
    atclient_atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atclient_get_public_encryption_key: %d\n", ret);
    return ret;
  }
  ret = atclient_get_public_encryption_key(ctx, recipient, recipient_public_encryption_key);
  if (ret != 0) {
    atclient_atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atclient_get_public_encryption_key: %d\n", ret);
    return ret;
  }

  // generate a new aes key
  const size_t keybase64len = 45;
  unsigned char new_shared_encryption_key_b64[keybase64len];
  memset(new_shared_encryption_key_b64, 0, keybase64len);
  size_t keybase64olen = 0;
  ret = atchops_aes_generate_keybase64(new_shared_encryption_key_b64, keybase64len, &keybase64olen, ATCHOPS_AES_256);
  if (ret != 0) {
    atclient_atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR,
                          "atchops_aes_generate_keybase64: %d\n; Error generating key: keybase64: %.*s\n", ret,
                          (int)keybase64olen, new_shared_encryption_key_b64);
    return ret;
  }

  const size_t ciphertextlen = 1024;
  size_t ciphertextolen = 0;

  // encrypt new shared key with client's public key
  atchops_rsakey_publickey client_publickey;
  atchops_rsakey_publickey_init(&client_publickey);

  ret = atchops_rsakey_populate_publickey(&client_publickey, client_public_encryption_key,
                                          strlen(client_public_encryption_key));
  if (ret != 0) {
    printf("atchops_rsakey_populate_publickey (failed): %d\n", ret);
    return ret;
  }

  unsigned char new_shared_encryption_key_b64_encrypted_with_client_public_key_b64[ciphertextlen];
  memset(new_shared_encryption_key_b64_encrypted_with_client_public_key_b64, 0, ciphertextlen);

  ret = atchops_rsa_encrypt(client_publickey, (const unsigned char *)new_shared_encryption_key_b64, keybase64len,
                            new_shared_encryption_key_b64_encrypted_with_client_public_key_b64, ciphertextlen,
                            &ciphertextolen);
  if (ret != 0) {
    printf("atchops_rsa_encrypt (failed): %d\n", ret);
    return ret;
  }

  // encrypt new shared key with recipient's public key
  atchops_rsakey_publickey recipient_publickey;
  atchops_rsakey_publickey_init(&recipient_publickey);

  ret = atchops_rsakey_populate_publickey(&recipient_publickey, recipient_public_encryption_key,
                                          strlen(recipient_public_encryption_key));
  if (ret != 0) {
    printf("atchops_rsakey_populate_publickey (failed): %d\n", ret);
    return ret;
  }

  unsigned char new_shared_encryption_key_b64_encrypted_with_recipient_public_key_b64[ciphertextlen];
  memset(new_shared_encryption_key_b64_encrypted_with_recipient_public_key_b64, 0, ciphertextlen);

  ret = atchops_rsa_encrypt(recipient_publickey, (const unsigned char *)new_shared_encryption_key_b64, keybase64len,
                            new_shared_encryption_key_b64_encrypted_with_recipient_public_key_b64, ciphertextlen,
                            &ciphertextolen);
  if (ret != 0) {
    printf("atchops_rsa_encrypt (failed): %d\n", ret);
    return ret;
  }

  short client_with_at_len = (short)strlen(ctx->atsign.atsign);
  short recipient_without_at_len = (short)strlen(recipient->without_prefix_str);

  // save encrypted key for us
  // update:shared_key.recipient@client key\r\n\0
  char *command1_prefix = "update:shared_key.";
  const short command1_prefix_len = 18;

  short command1_len = command1_prefix_len + recipient_without_at_len + client_with_at_len +
                       strlen((char *)new_shared_encryption_key_b64_encrypted_with_client_public_key_b64) + 4;
  char command1[command1_len];
  snprintf(command1, command1_len, "update:shared_key.%s%s %s\r\n", recipient->without_prefix_str, ctx->atsign.atsign,
           new_shared_encryption_key_b64_encrypted_with_client_public_key_b64);

  // save encrypted key for them
  // ttr = 3888000 (45 days)
  // update:ttr:3888000:recipient:shared_key@client key\r\n\0
  char *command2_prefix = "update:ttr:3888000:";
  const short command2_prefix_len = 19;

  short command2_len = command2_prefix_len + recipient_without_at_len + client_with_at_len +
                       strlen((char *)new_shared_encryption_key_b64_encrypted_with_recipient_public_key_b64) + 5;
  char command2[command2_len];
  snprintf(command2, command2_len, "update:ttr:3888000:%s:shared_key%s %s\r\n", recipient->without_prefix_str,
           ctx->atsign.atsign, new_shared_encryption_key_b64_encrypted_with_recipient_public_key_b64);

  // copy new aes key to func parameter
  memcpy(enc_key_shared_by_me, new_shared_encryption_key_b64, 45);

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

  ret = atclient_connection_send(&(ctx->secondary_connection), (unsigned char *)command, strlen((char *)command), recv,
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
    atclient_atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atchops_rsa_decrypt: %d; error:AT0015-key not found\n",
                          ret);
    ret = 1;
    return ret;
  }

  return 0;
}

void atclient_free(atclient *ctx) {
  atclient_connection_free(&(ctx->root_connection));
  atclient_connection_free(&(ctx->secondary_connection));
}
