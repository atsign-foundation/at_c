#include "atclient/atclient.h"
#include "atclient/atkey.h"
#include "atclient/atstr.h"
#include "atclient/constants.h"
#include "atclient/encryption_key_helpers.h"
#include "atclient/stringutils.h"
#include "atlogger/atlogger.h"
#include <atchops/aesctr.h>
#include <atchops/base64.h>
#include <atchops/iv.h>
#include <atchops/rsa.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>

#define TAG "atclient_put"

int atclient_put(atclient *atclient, atclient_connection *root_conn, atclient_atkey *atkey, const char *value,
                 const size_t valuelen, int *commitid) {
  int ret = 1;

  // make sure shared by is atclient->atsign.atsign
  if (strncmp(atkey->sharedby.str, atclient->atsign.atsign, atkey->sharedby.olen) != 0) {
    atclient_atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atkey's sharedby is not atclient's atsign\n");
    return ret;
  }

  // 1. initialize variables
  const size_t atkeystrlen = ATCLIENT_ATKEY_FULL_LEN;
  char atkeystr[atkeystrlen];
  memset(atkeystr, 0, sizeof(char) * atkeystrlen);
  size_t atkeystrolen = 0;

  const size_t recvlen = 4096;
  unsigned char recv[recvlen];
  memset(recv, 0, sizeof(unsigned char) * recvlen);
  size_t recvolen = 0;

  const size_t ivlen = ATCHOPS_IV_BUFFER_SIZE;
  unsigned char iv[ATCHOPS_IV_BUFFER_SIZE];
  memset(iv, 0, sizeof(unsigned char) * ivlen);

  const size_t ivbase64size = 64;
  char ivbase64[ivbase64size];
  memset(ivbase64, 0, sizeof(char) * ivbase64size);
  size_t ivbase64len = 0;

  const size_t metadataprotocolstrlen = 2048;
  char metadataprotocolstr[metadataprotocolstrlen];
  memset(metadataprotocolstr, 0, sizeof(char) * metadataprotocolstrlen);
  size_t metadataprotocolstrolen = 0;

  const size_t ciphertextsize = 4096;
  unsigned char ciphertext[ciphertextsize];
  memset(ciphertext, 0, sizeof(unsigned char) * ciphertextsize);
  size_t ciphertextlen = 0;

  const size_t ciphertextbase64size = 4096;
  char ciphertextbase64[ciphertextbase64size];
  memset(ciphertextbase64, 0, sizeof(char) * ciphertextbase64size);
  size_t ciphertextbase64len = 0;

  const size_t sharedenckeybase64size = 45;
  char sharedenckeybase64[sharedenckeybase64size];
  memset(sharedenckeybase64, 0, sizeof(char) * sharedenckeybase64size);

  char *cmdbuffer = NULL;

  // 2. build update: command
  ret = atclient_atkey_to_string(atkey, atkeystr, atkeystrlen, &atkeystrolen);
  if (ret != 0) {
    atclient_atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atclient_atkey_to_string: %d\n", ret);
    goto exit;
  }

  ret = atclient_atkey_metadata_to_protocol_str(&(atkey->metadata), metadataprotocolstr, metadataprotocolstrlen,
                                                &metadataprotocolstrolen);
  if (ret != 0) {
    atclient_atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atclient_atkey_metadata_to_protocolstr: %d\n", ret);
    goto exit;
  }

  if (atkey->atkeytype == ATCLIENT_ATKEY_TYPE_PUBLICKEY) {
    // no encryption
    memcpy(ciphertextbase64, value, valuelen);
    ciphertextbase64len = valuelen;
  } else if (atkey->atkeytype == ATCLIENT_ATKEY_TYPE_SELFKEY) {
    const size_t selfencryptionkeysize = ATCHOPS_AES_256 / 8;
    unsigned char selfencryptionkey[selfencryptionkeysize];
    memset(selfencryptionkey, 0, sizeof(unsigned char) * (ATCHOPS_AES_256 / 8));
    size_t selfencryptionkeylen = 0;
    ret = atchops_base64_decode(atclient->atkeys.selfencryptionkeystr.str, atclient->atkeys.selfencryptionkeystr.olen,
                                selfencryptionkey, selfencryptionkeysize, &selfencryptionkeylen);
    if (ret != 0) {
      atclient_atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atchops_base64_decode: %d\n", ret);
      goto exit;
    }

    ret = atchops_aesctr_encrypt(selfencryptionkey, ATCHOPS_AES_256, iv, (unsigned char *)value, valuelen,
                                 ciphertext, ciphertextsize, &ciphertextlen);
    if (ret != 0) {
      atclient_atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atchops_aesctr_encrypt: %d\n", ret);
      goto exit;
    }

    ret = atchops_base64_encode(ciphertext, ciphertextlen, ciphertextbase64, ciphertextbase64size, &ciphertextbase64len);
    if (ret != 0) {
      atclient_atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atchops_base64_encode: %d\n", ret);
      goto exit;
    }
  } else if (atkey->atkeytype == ATCLIENT_ATKEY_TYPE_SHAREDKEY) {
    // encrypt with shared encryption key

    // get our AES shared key
    // if it doesn't exist, create one for us and create one for the other person
    // create one for us -> encrypted with our self encryption key
    // create one for the other person -> encrypted with their public encryption key
    atclient_atsign recipient;
    atclient_atsign_init(&recipient, atkey->sharedwith.str);

    ret = atclient_get_shared_encryption_key_shared_by_me(atclient, &recipient, sharedenckeybase64, true);
    if (ret != 0) {
      atclient_atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atclient_get_encryption_key_shared_by_me: %d\n", ret);
      goto exit;
    }

    // encrypt with shared encryption key
    ret = atchops_iv_generate(iv);
    if (ret != 0) {
      atclient_atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atchops_iv_generate: %d\n", ret);
      goto exit;
    }

    ret = atchops_base64_encode(iv, ATCHOPS_IV_BUFFER_SIZE, ivbase64, ivbase64size, &ivbase64len);
    if (ret != 0) {
      atclient_atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atchops_base64_encode: %d\n", ret);
      goto exit;
    }

    ret = atclient_atkey_metadata_set_ivnonce(&(atkey->metadata), ivbase64, ivbase64len);
    if (ret != 0) {
      atclient_atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atclient_atkey_metadata_set_ivnonce: %d\n", ret);
      goto exit;
    }

    unsigned char sharedenckey[ATCHOPS_AES_256 / 8];
    memset(sharedenckey, 0, sizeof(unsigned char) * (ATCHOPS_AES_256 / 8));
    size_t sharedenckeylen = 0;
    ret = atchops_base64_decode(sharedenckeybase64, strlen(sharedenckeybase64), sharedenckey, sizeof(sharedenckey),
                                &sharedenckeylen);
    if (ret != 0) {
      atclient_atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atchops_base64_decode: %d\n", ret);
      goto exit;
    }

    ret = atchops_aesctr_encrypt(sharedenckey, ATCHOPS_AES_256, iv, (unsigned char *)value, valuelen, ciphertext,
                                 ciphertextsize, &ciphertextlen);
    if (ret != 0) {
      atclient_atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atchops_aesctr_encrypt: %d\n", ret);
      goto exit;
    }

    ret = atchops_base64_encode(ciphertext, ciphertextlen, ciphertextbase64, ciphertextbase64size, &ciphertextbase64len);
    if (ret != 0) {
      atclient_atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atchops_base64_encode: %d\n", ret);
      goto exit;
    }
  }

  size_t cmdbufferlen = strlen(" update:\r\n") + atkeystrolen + ciphertextbase64len + 1; // + 1 for null terminator

  ret = atclient_atkey_metadata_to_protocol_str(&(atkey->metadata), metadataprotocolstr, metadataprotocolstrlen,
                                                &metadataprotocolstrolen);
  if (ret != 0) {
    atclient_atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atclient_atkey_metadata_to_protocolstr: %d\n", ret);
    goto exit;
  }

  if (metadataprotocolstrolen > 0) {
    cmdbufferlen += metadataprotocolstrolen;
  }
  cmdbuffer = malloc(sizeof(char) * cmdbufferlen);
  memset(cmdbuffer, 0, sizeof(char) * cmdbufferlen);

  snprintf(cmdbuffer, cmdbufferlen, "update%.*s:%.*s %.*s\r\n", (int)metadataprotocolstrolen, metadataprotocolstr,
           (int)atkeystrolen, atkeystr, (int)ciphertextbase64len, ciphertextbase64);

  ret = atclient_connection_send(&(atclient->secondary_connection), (unsigned char *)cmdbuffer, cmdbufferlen - 1, recv,
                                 recvlen, &recvolen);
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

  if (commitid != NULL) {
    char *recvwithoutdata = (char *)recv + 5;
    *commitid = atoi(recvwithoutdata);
  }

  ret = 0;
  goto exit;
exit: {

  free(cmdbuffer);
  return ret;
}
}
