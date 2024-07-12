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

static int atclient_put_valid_args_check(atclient *atclient, atclient_atkey *atkey, const char *value, const size_t valuelen, int *commitid);

int atclient_put(atclient *atclient, atclient_atkey *atkey, const char *value, const size_t valuelen, int *commitid) {
  int ret = 1;

  /*
   * 1. Check if valid arguments were passed
   */
  if((ret = atclient_put_valid_args_check(atclient, atkey, value, valuelen, commitid)) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atclient_put_valid_args_check: %d\n", ret);
    return ret;
  }

  /*
   * 2. Allocate variables
   */
  char *atkeystr = NULL;

  const size_t recvsize = 4096; // sufficient buffer size to 1. receive data from a `llookup:shared_key@<>` and 2. to
                                // receive commmit id from `update:`
  unsigned char *recv = NULL;
  if (!atclient->async_read) {
    recv = malloc(sizeof(unsigned char) * recvsize);
    memset(recv, 0, sizeof(unsigned char) * recvsize);
  }
  size_t recvlen = 0;

  const short ivsize = ATCHOPS_IV_BUFFER_SIZE;
  unsigned char iv[ATCHOPS_IV_BUFFER_SIZE];
  memset(iv, 0, sizeof(unsigned char) * ivsize);

  const size_t ivbase64size = atchops_base64_encoded_size(ivsize) + 1;
  char ivbase64[ivbase64size];
  memset(ivbase64, 0, sizeof(char) * ivbase64size);
  size_t ivbase64len = 0;

  const size_t ciphertextsize = atchops_aes_ctr_ciphertext_size(valuelen) + 1;
  unsigned char ciphertext[ciphertextsize];
  memset(ciphertext, 0, sizeof(unsigned char) * ciphertextsize);
  size_t ciphertextlen = 0;

  const size_t ciphertextbase64size = atchops_base64_encoded_size(ciphertextsize) + 1;
  char ciphertextbase64[ciphertextbase64size];
  memset(ciphertextbase64, 0, sizeof(char) * ciphertextbase64size);
  size_t ciphertextbase64len = 0;

  const size_t sharedenckeybase64size = atchops_base64_encoded_size(ATCHOPS_AES_256 / 8) + 1;
  char sharedenckeybase64[sharedenckeybase64size];
  memset(sharedenckeybase64, 0, sizeof(char) * sharedenckeybase64size);

  char *cmdbuffer = NULL;
  char *metadata_protocol_str = NULL;

  // 2. build update: command
  ret = atclient_atkey_to_string(atkey, &atkeystr);
  if (ret != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atclient_atkey_to_string: %d\n", ret);
    goto exit;
  }
  const size_t atkeystrlen = strlen(atkeystr);

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
    // create one for us -> encrypted with our self encryption key
    // create one for the other person -> encrypted with their public encryption key
    atclient_atsign recipient;
    atclient_atsign_init(&recipient, atkey->sharedwith.str);

    ret = atclient_get_shared_encryption_key_shared_by_me(atclient, &recipient, sharedenckeybase64, true);
    if (ret != 0) {
      atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atclient_get_encryption_key_shared_by_me: %d\n", ret);
      goto error_cleanup;
    }

    // encrypt with shared encryption key
    ret = atchops_iv_generate(iv);
    if (ret != 0) {
      atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atchops_iv_generate: %d\n", ret);
      goto error_cleanup;
    }

    ret = atchops_base64_encode(iv, ATCHOPS_IV_BUFFER_SIZE, (unsigned char *)ivbase64, ivbase64size, &ivbase64len);
    if (ret != 0) {
      atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atchops_base64_encode: %d\n", ret);
      goto error_cleanup;
    }

    ret = atclient_atkey_metadata_set_ivnonce(&(atkey->metadata), ivbase64, ivbase64len);
    if (ret != 0) {
      atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atclient_atkey_metadata_set_ivnonce: %d\n", ret);
      goto error_cleanup;
    }

    unsigned char sharedenckey[ATCHOPS_AES_256 / 8];
    memset(sharedenckey, 0, sizeof(unsigned char) * (ATCHOPS_AES_256 / 8));
    size_t sharedenckeylen = 0;
    ret = atchops_base64_decode((unsigned char *)sharedenckeybase64, strlen(sharedenckeybase64), sharedenckey,
                                sizeof(sharedenckey), &sharedenckeylen);
    if (ret != 0) {
      atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atchops_base64_decode: %d\n", ret);
      goto error_cleanup;
    }

    ret = atchops_aesctr_encrypt(sharedenckey, ATCHOPS_AES_256, iv, (unsigned char *)value, valuelen, ciphertext,
                                 ciphertextsize, &ciphertextlen);
    if (ret != 0) {
      atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atchops_aesctr_encrypt: %d\n", ret);
      goto error_cleanup;
    }

    ret = atchops_base64_encode(ciphertext, ciphertextlen, (unsigned char *)ciphertextbase64, ciphertextbase64size,
                                &ciphertextbase64len);
    if (ret != 0) {
      atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atchops_base64_encode: %d\n", ret);
      goto error_cleanup;
    }

    goto non_error_cleanup;

  error_cleanup: {
    atclient_atsign_free(&recipient);
    goto exit;
  }

  non_error_cleanup: { atclient_atsign_free(&recipient); }
  }

  size_t cmdbufferlen = strlen(" update:\r\n") + atkeystrlen + ciphertextbase64len + 1; // + 1 for null terminator

  ret = atclient_atkey_metadata_to_protocol_str(&(atkey->metadata), &(metadata_protocol_str));
  if (ret != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atclient_atkey_metadata_to_protocolstr: %d\n", ret);
    goto exit;
  }

  const size_t metadata_protocol_str_len = strlen(metadata_protocol_str);

  if (metadata_protocol_str_len > 0) {
    cmdbufferlen += metadata_protocol_str_len;
  }
  cmdbuffer = malloc(sizeof(char) * cmdbufferlen);
  memset(cmdbuffer, 0, sizeof(char) * cmdbufferlen);

  snprintf(cmdbuffer, cmdbufferlen, "update%.*s:%.*s %.*s\r\n", (int)metadata_protocol_str_len, metadata_protocol_str,
           (int)atkeystrlen, atkeystr, (int)ciphertextbase64len, ciphertextbase64);

  ret = atclient_connection_send(&(atclient->atserver_connection), (unsigned char *)cmdbuffer, cmdbufferlen - 1, recv,
                                 recvsize, &recvlen);
  if (ret != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atclient_connection_send: %d\n", ret);
    goto exit;
  } else if (atclient->async_read) {
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
  if (!atclient->async_read) {
    free(recv);
  }
  free(cmdbuffer);
  free(metadata_protocol_str);
  free(atkeystr);
  return ret;
}
}

static int atclient_put_valid_args_check(atclient *atclient, atclient_atkey *atkey, const char *value, const size_t valuelen, int *commitid) 
{
{
  int ret = 1;
  if (atclient == NULL) {
    ret = 1;
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atclient is NULL\n");
    return ret;
  }

  if (atkey == NULL) {
    ret = 1;
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atkey is NULL\n");
    return ret;
  }

  if (value == NULL) {
    ret = 1;
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "value is NULL\n");
    return ret;
  }

  if (valuelen == 0) {
    ret = 1;
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "valuelen is 0\n");
    return ret;
  }

  // make sure shared by is atclient->atsign.atsign
  if (strncmp(atkey->sharedby.str, atclient->atsign.atsign, atkey->sharedby.len) != 0) {
    ret = 1;
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atkey's sharedby is not atclient's atsign\n");
    return ret;
  }

  if (atclient->async_read) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR,
                 "atclient_put cannot be called from an async_read atclient, it will cause a race condition\n");
    return ret;
  }
}
}