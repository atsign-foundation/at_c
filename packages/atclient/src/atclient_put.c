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

int atclient_put(atclient *atclient, atclient_atkey *atkey, const char *value, const size_t valuelen, int *commitid) {
  int ret = 1;

  char *cmdbuffer = NULL;
  char *metadataprotocolstr = NULL;

  // make sure shared by is atclient->atsign.atsign
  if (strncmp(atkey->sharedby.str, atclient->atsign.atsign, atkey->sharedby.len) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atkey's sharedby is not atclient's atsign\n");
    return ret;
  }

  // 1. initialize variables
  const size_t atkeystrsize = ATCLIENT_ATKEY_FULL_LEN;
  char atkeystr[atkeystrsize];
  memset(atkeystr, 0, sizeof(char) * atkeystrsize);
  size_t atkeystrlen = 0;

  const size_t recvsize = 4096;
  unsigned char recv[recvsize];
  memset(recv, 0, sizeof(unsigned char) * recvsize);
  size_t recvlen = 0;

  const short ivsize = ATCHOPS_IV_BUFFER_SIZE;
  unsigned char iv[ATCHOPS_IV_BUFFER_SIZE];
  memset(iv, 0, sizeof(unsigned char) * ivsize);

  const size_t ivbase64size = 64;
  char ivbase64[ivbase64size];
  memset(ivbase64, 0, sizeof(char) * ivbase64size);
  size_t ivbase64len = 0;

  const size_t ciphertextsize = 4096;
  unsigned char ciphertext[ciphertextsize];
  memset(ciphertext, 0, sizeof(unsigned char) * ciphertextsize);
  size_t ciphertextlen = 0;

  const size_t ciphertextbase64size = 4096;
  char ciphertextbase64[ciphertextbase64size];
  memset(ciphertextbase64, 0, sizeof(char) * ciphertextbase64size);
  size_t ciphertextbase64len = 0;

  const size_t sharedenckeysize = ATCHOPS_AES_256 / 8;
  unsigned char sharedenckey[sharedenckeysize];
  memset(sharedenckey, 0, sizeof(unsigned char) * (sharedenckeysize));
  size_t sharedenckeylen = 0;

  // 2. build update: command
  ret = atclient_atkey_to_string(atkey, atkeystr, atkeystrsize, &atkeystrlen);
  if (ret != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atclient_atkey_to_string: %d\n", ret);
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
    ret = atchops_base64_decode((const unsigned char *)atclient->atkeys.selfencryptionkeystr.str,
                                atclient->atkeys.selfencryptionkeystr.len, selfencryptionkey, selfencryptionkeysize,
                                &selfencryptionkeylen);
    if (ret != 0) {
      atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atchops_base64_decode: %d\n", ret);
      goto exit;
    }

    ret = atchops_aesctr_encrypt(selfencryptionkey, ATCHOPS_AES_256, iv, (unsigned char *)value, valuelen, ciphertext,
                                 ciphertextsize, &ciphertextlen);
    if (ret != 0) {
      atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atchops_aesctr_encrypt: %d\n", ret);
      goto exit;
    }

    ret = atchops_base64_encode(ciphertext, ciphertextlen, (unsigned char *)ciphertextbase64, ciphertextbase64size,
                                &ciphertextbase64len);
    if (ret != 0) {
      atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atchops_base64_encode: %d\n", ret);
      goto exit;
    }
  } else if (atkey->atkeytype == ATCLIENT_ATKEY_TYPE_SHAREDKEY) {
    // encrypt with shared encryption key

    // get our AES shared key
    // if it doesn't exist, create one for us and create one for the other person
    if ((ret = atclient_get_shared_encryption_key_shared_by_me(atclient, atkey->sharedwith.str, atkey->sharedwith.len,
                                                               sharedenckey)) == ATCLIENT_ERR_AT0015_KEY_NOT_FOUND) {
      atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_INFO,
                   "Shared encryption key not found, creating one for me and the other atServer.\n");
      if ((ret = atclient_create_shared_encryption_keypair_for_me_and_other(
               atclient, atkey->sharedwith.str, atkey->sharedwith.len, sharedenckey)) != 0) {
        atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR,
                     "atclient_create_shared_encryption_keypair_for_me_and_other: %d\n", ret);
        goto exit;
      }
    } else if (ret != 0) {
      atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atclient_get_shared_encryption_key_shared_by_me: %d\n", ret);
      goto exit;
    }

    // encrypt with shared encryption key
    ret = atchops_iv_generate(iv);
    if (ret != 0) {
      atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atchops_iv_generate: %d\n", ret);
      goto exit;
    }

    ret = atchops_base64_encode(iv, ATCHOPS_IV_BUFFER_SIZE, (unsigned char *)ivbase64, ivbase64size, &ivbase64len);
    if (ret != 0) {
      atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atchops_base64_encode: %d\n", ret);
      goto exit;
    }

    ret = atclient_atkey_metadata_set_ivnonce(&(atkey->metadata), ivbase64, ivbase64len);
    if (ret != 0) {
      atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atclient_atkey_metadata_set_ivnonce: %d\n", ret);
      goto exit;
    }

    ret = atchops_aesctr_encrypt(sharedenckey, ATCHOPS_AES_256, iv, (unsigned char *)value, valuelen, ciphertext,
                                 ciphertextsize, &ciphertextlen);
    if (ret != 0) {
      atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atchops_aesctr_encrypt: %d\n", ret);
      goto exit;
    }

    ret = atchops_base64_encode(ciphertext, ciphertextlen, (unsigned char *)ciphertextbase64, ciphertextbase64size,
                                &ciphertextbase64len);
    if (ret != 0) {
      atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atchops_base64_encode: %d\n", ret);
      goto exit;
    }
  }

  size_t cmdbufferlen = strlen(" update:\r\n") + atkeystrlen + ciphertextbase64len + 1; // + 1 for null terminator

  const size_t metadataprotocolstrsize = atclient_atkey_metadata_protocol_strlen(&(atkey->metadata));
  metadataprotocolstr = malloc(sizeof(char) * metadataprotocolstrsize);
  memset(metadataprotocolstr, 0, sizeof(char) * metadataprotocolstrsize);
  size_t metadataprotocolstrlen = 0;

  ret = atclient_atkey_metadata_to_protocol_str(&(atkey->metadata), metadataprotocolstr, metadataprotocolstrsize,
                                                &metadataprotocolstrlen);
  if (ret != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atclient_atkey_metadata_to_protocolstr: %d\n", ret);
    goto exit;
  }

  if (metadataprotocolstrlen > 0) {
    cmdbufferlen += metadataprotocolstrlen;
  }
  cmdbuffer = malloc(sizeof(char) * cmdbufferlen);
  memset(cmdbuffer, 0, sizeof(char) * cmdbufferlen);

  snprintf(cmdbuffer, cmdbufferlen, "update%.*s:%.*s %.*s\r\n", (int)metadataprotocolstrlen, metadataprotocolstr,
           (int)atkeystrlen, atkeystr, (int)ciphertextbase64len, ciphertextbase64);

  ret = atclient_connection_send(&(atclient->secondary_connection), (unsigned char *)cmdbuffer, cmdbufferlen - 1, recv,
                                 recvsize, &recvlen);
  if (ret != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atclient_connection_send: %d\n", ret);
    goto exit;
  }

  if (!atclient_stringutils_starts_with((char *)recv, recvlen, "data:", 5)) {
    ret = 1;
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "recv was \"%.*s\" and did not have prefix \"data:\"\n",
                 (int)recvlen, recv);
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
  free(metadataprotocolstr);
  return ret;
}
}
