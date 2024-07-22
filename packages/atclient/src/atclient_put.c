#include "atclient/atclient.h"
#include "atclient/atkey.h"
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

static int atclient_put_validate_args(const atclient *ctx, const atclient_atkey *atkey, const char *value,
                                      const size_t valuelen, const int *commitid);

int atclient_put(atclient *ctx, atclient_atkey *atkey, const char *value, const size_t valuelen, int *commitid) {
  int ret = 1;

  /*
   * 1. Check if valid arguments were passed
   */
  if ((ret = atclient_put_validate_args(ctx, atkey, value, valuelen, commitid)) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atclient_put_validate_args: %d\n", ret);
    return ret;
  }

  /*
   * 2. Allocate variables
   */
  char *atkeystr = NULL;
  size_t atkeystrlen = 0;

  char *cmdbuffer = NULL;
  size_t cmdbuffersize = 0;

  char *metadataprotocolstr = NULL;
  size_t metadataprotocolstrlen = 0;

  const short ivsize = ATCHOPS_IV_BUFFER_SIZE;
  unsigned char iv[ATCHOPS_IV_BUFFER_SIZE];
  memset(iv, 0, sizeof(unsigned char) * ivsize);

  const size_t ivbase64size = atchops_base64_encoded_size(ivsize) + 1;
  char ivbase64[ivbase64size];
  memset(ivbase64, 0, sizeof(char) * ivbase64size);
  size_t ivbase64len = 0;

  const size_t ciphertextsize = atchops_aesctr_ciphertext_size(valuelen) + 1;
  unsigned char ciphertext[ciphertextsize];
  memset(ciphertext, 0, sizeof(unsigned char) * ciphertextsize);
  size_t ciphertextlen = 0;

  const size_t ciphertextbase64size = atchops_base64_encoded_size(ciphertextsize) + 1;
  char ciphertextbase64[ciphertextbase64size];
  memset(ciphertextbase64, 0, sizeof(char) * ciphertextbase64size);
  size_t ciphertextbase64len = 0;

  const size_t sharedenckeysize = ATCHOPS_AES_256 / 8;
  unsigned char sharedenckey[sharedenckeysize];
  memset(sharedenckey, 0, sizeof(unsigned char) * sharedenckeysize);
  size_t sharedenckeylen = 0;

  const size_t sharedenckeybase64size = atchops_base64_encoded_size(sharedenckeysize) + 1;
  char sharedenckeybase64[sharedenckeybase64size];
  memset(sharedenckeybase64, 0, sizeof(char) * sharedenckeybase64size);
  size_t sharedenckeybase64len = 0;

  const size_t recvsize = 4096; // sufficient buffer size to 1. receive data from a `llookup:shared_key@<>` and 2. to
                                // receive commmit id from `update:`
  unsigned char *recv = NULL;
  if (!ctx->async_read) {
    recv = malloc(sizeof(unsigned char) * recvsize);
    if (recv == NULL) {
      ret = 1;
      atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "Failed to allocate memory for recv\n");
      goto exit;
    }
    memset(recv, 0, sizeof(unsigned char) * recvsize);
  }
  size_t recvlen = 0;

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

  if (atkey_type == ATCLIENT_ATKEY_TYPE_PUBLICKEY) {
    // 3a.1 no encryption
    memcpy(ciphertextbase64, value, valuelen);
    ciphertextbase64len = valuelen;
  } else if (atkey_type == ATCLIENT_ATKEY_TYPE_SELFKEY) {
    // 3a.2 encrypt with self encryption key
    const size_t selfencryptionkeysize = ATCHOPS_AES_256 / 8;
    unsigned char selfencryptionkey[selfencryptionkeysize];
    memset(selfencryptionkey, 0, sizeof(unsigned char) * selfencryptionkeysize);
    size_t selfencryptionkeylen = 0;

    if ((ret = atchops_base64_decode((const unsigned char *)ctx->atkeys.selfencryptionkeybase64,
                                     strlen(ctx->atkeys.selfencryptionkeybase64), selfencryptionkey,
                                     selfencryptionkeysize, &selfencryptionkeylen)) != 0) {
      atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atchops_base64_decode: %d\n", ret);
      goto exit;
    }

    if ((ret = atchops_aesctr_encrypt(selfencryptionkey, ATCHOPS_AES_256, iv, (unsigned char *)value, valuelen,
                                      ciphertext, ciphertextsize, &ciphertextlen)) != 0) {
      atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atchops_aesctr_encrypt: %d\n", ret);
      goto exit;
    }

    if ((ret = atchops_base64_encode(ciphertext, ciphertextlen, (unsigned char *)ciphertextbase64, ciphertextbase64size,
                                     &ciphertextbase64len)) != 0) {
      atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atchops_base64_encode: %d\n", ret);
      goto exit;
    }
  } else if (atkey_type == ATCLIENT_ATKEY_TYPE_SHAREDKEY) {
    // 3aA.3 encrypt with shared encryption key

    // get our AES shared key
    // if it doesn't exist, create one for us and create one for the other person
    // create one for us -> encrypted with our self encryption key
    // create one for the other person -> encrypted with their public encryption key
    char *recipient_atsign = atkey->sharedwith;

    if ((ret = atclient_get_shared_encryption_key_shared_by_me(ctx, recipient_atsign, sharedenckey)) != 0) {
      atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atclient_get_shared_encryption_key_shared_by_me: %d\n", ret);
      goto exit;
    }

    if ((ret = atchops_iv_generate(iv)) != 0) {
      atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atchops_iv_generate: %d\n", ret);
      goto exit;
    }

    if ((ret = atchops_base64_encode(iv, ATCHOPS_IV_BUFFER_SIZE, (unsigned char *)ivbase64, ivbase64size,
                                     &ivbase64len)) != 0) {
      atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atchops_base64_encode: %d\n", ret);
      goto exit;
    }

    if ((ret = atclient_atkey_metadata_set_ivnonce(&(atkey->metadata), ivbase64)) != 0) {
      atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atclient_atkey_metadata_set_ivnonce: %d\n", ret);
      goto exit;
    }

    if ((ret = atchops_aesctr_encrypt(sharedenckey, ATCHOPS_AES_256, iv, (unsigned char *)value, valuelen, ciphertext,
                                      ciphertextsize, &ciphertextlen)) != 0) {
      atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atchops_aesctr_encrypt: %d\n", ret);
      goto exit;
    }

    if ((ret = atchops_base64_encode(ciphertext, ciphertextlen, (unsigned char *)ciphertextbase64, ciphertextbase64size,
                                     &ciphertextbase64len)) != 0) {
      atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atchops_base64_encode: %d\n", ret);
      goto exit;
    }
  }

  // 3b. Build the command

  if ((ret = atclient_atkey_to_string(atkey, &atkeystr)) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atclient_atkey_to_string: %d\n", ret);
    goto exit;
  }
  atkeystrlen = strlen(atkeystr);

  if ((ret = atclient_atkey_metadata_to_protocol_str(&(atkey->metadata), &(metadataprotocolstr))) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atclient_atkey_metadata_to_protocolstr: %d\n", ret);
    goto exit;
  }
  metadataprotocolstrlen = strlen(metadataprotocolstr);

  cmdbuffersize = strlen("update: \r\n") + metadataprotocolstrlen + atkeystrlen + ciphertextbase64len +
                  1; // + 1 for null terminator
  cmdbuffer = malloc(sizeof(char) * cmdbuffersize);
  if (cmdbuffer == NULL) {
    ret = 1;
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "Failed to allocate memory for cmdbuffer\n");
    goto exit;
  }
  memset(cmdbuffer, 0, sizeof(char) * cmdbuffersize);
  snprintf(cmdbuffer, cmdbuffersize, "update%.*s:%.*s %.*s\r\n", (int)metadataprotocolstrlen, metadataprotocolstr,
           (int)atkeystrlen, atkeystr, (int)ciphertextbase64len, ciphertextbase64);

  /*
   * 4. Send the command
   */
  if ((ret = atclient_connection_send(&(ctx->atserver_connection), (unsigned char *)cmdbuffer, cmdbuffersize - 1, recv,
                                      recvsize, &recvlen)) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atclient_connection_send: %d\n", ret);
    goto exit;
  }

  if (ctx->async_read) {
    goto exit;
  }

  if (!atclient_stringutils_starts_with((char *)recv, "data:")) {
    ret = 1;
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "recv was \"%.*s\" and did not have prefix \"data:\"\n",
                 (int)recvlen, recv);
    goto exit;
  }

  /*
   * 5. Return the commit id.
   */

  if (commitid != NULL) {
    char *recvwithoutdata = (char *)recv + 5;
    *commitid = atoi(recvwithoutdata);
  }

  ret = 0;
  goto exit;
exit: {
  if (!ctx->async_read) {
    free(recv);
  }
  free(cmdbuffer);
  free(metadataprotocolstr);
  free(atkeystr);
  return ret;
}
}


static int atclient_put_validate_args(const atclient *ctx, const atclient_atkey *atkey, const char *value,
                                      const size_t valuelen, const int *commitid) {
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

  if (valuelen == 0) {
    ret = 1;
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "valuelen is 0\n");
    goto exit;
  }

  if (!atclient_atkey_is_sharedby_initialized(atkey) || strlen(atkey->sharedby) <= 0) {
    ret = 1;
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atkey's sharedby is not initialized or is empty\n");
    goto exit;
  }

  if (strcmp(atkey->sharedby, ctx->atsign) != 0) {
    ret = 1;
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atkey's sharedby is not atclient's atsign\n");
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