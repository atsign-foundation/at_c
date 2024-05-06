#include "atclient/atkeys.h"
#include "atclient/atstr.h"
#include "atlogger/atlogger.h"
#include <atchops/aesctr.h>
#include <atchops/base64.h>
#include <atchops/iv.h>
#include <atchops/rsa.h>
#include <atchops/rsakey.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>

#include <stdio.h> // TODO Remove

#define TAG "atkeys"

void atclient_atkeys_init(atclient_atkeys *atkeys) {
  memset(atkeys, 0, sizeof(atclient_atkeys));

  atclient_atstr_init(&(atkeys->pkampublickeystr), 4096);
  atchops_rsakey_publickey_init(&(atkeys->pkampublickey));

  atclient_atstr_init(&(atkeys->pkamprivatekeystr), 4096);
  atchops_rsakey_privatekey_init(&(atkeys->pkamprivatekey));

  atclient_atstr_init(&(atkeys->encryptpublickeystr), 4096);
  atchops_rsakey_publickey_init(&(atkeys->encryptpublickey));

  atclient_atstr_init(&(atkeys->encryptprivatekeystr), 4096);
  atchops_rsakey_privatekey_init(&(atkeys->encryptprivatekey));

  atclient_atstr_init(&(atkeys->selfencryptionkeystr), 4096);
}

int atclient_atkeys_populate_from_strings(atclient_atkeys *atkeys, const char *aespkampublickeystr,
                                          const size_t aespkampublickeylen, const char *aespkamprivatekeystr,
                                          const size_t aespkamprivatekeylen, const char *aesencryptpublickeystr,
                                          const size_t aesencryptpublickeylen, const char *aesencryptprivatekeystr,
                                          const size_t aesencryptprivatekeylen, const char *selfencryptionkeystr,
                                          const size_t selfencryptionkeystrlen) {
  int ret = 1;

  unsigned char iv[ATCHOPS_IV_BUFFER_SIZE];
  memset(iv, 0, sizeof(unsigned char) * ATCHOPS_IV_BUFFER_SIZE);

  const size_t selfencryptionkeysize = ATCHOPS_AES_256 / 8;
  unsigned char selfencryptionkey[selfencryptionkeysize];
  memset(selfencryptionkey, 0, sizeof(unsigned char) * selfencryptionkeysize);
  size_t selfencryptionkeylen = 0;

  const size_t rsakeyencryptedsize = 2048;
  unsigned char rsakeyencrypted[rsakeyencryptedsize];
  memset(rsakeyencrypted, 0, sizeof(unsigned char) * rsakeyencryptedsize);
  size_t rsakeyencryptedlen = 0;;

  // 1. decrypt *.atKeys and populate atkeys struct

  // 1a. self encryption key
  ret = atclient_atstr_set(&(atkeys->selfencryptionkeystr), selfencryptionkeystr, selfencryptionkeystrlen);
  if (ret != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR,
                          "atclient_atstr_set: %d | failed to set selfencryptionkeystr\n", ret);
    goto exit;
  }

  ret = atchops_base64_decode((unsigned char *) atkeys->selfencryptionkeystr.str, atkeys->selfencryptionkeystr.len, selfencryptionkey,
                              selfencryptionkeysize, &selfencryptionkeylen);
  if (ret != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "tried base64 decoding selfencryption key: %d\n", ret);
    goto exit;
  }

  // 1b. pkam public key
  ret = atchops_base64_decode((unsigned char *)aespkampublickeystr, aespkampublickeylen, rsakeyencrypted,
                              rsakeyencryptedsize, &rsakeyencryptedlen);
  if (ret != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "tried base64 decoding pkam public key: %d\n", ret);
    goto exit;
  }

  ret = atchops_aesctr_decrypt(selfencryptionkey, ATCHOPS_AES_256, iv, rsakeyencrypted, rsakeyencryptedlen,
                               (unsigned char *) atkeys->pkampublickeystr.str, atkeys->pkampublickeystr.size,
                               &(atkeys->pkampublickeystr.len));
  if (ret != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR,
                          "atchops_aesctr_decrypt: %d | failed to decrypt pkam public key\n", ret);
    goto exit;
  }

  memset(rsakeyencrypted, 0, sizeof(unsigned char) * rsakeyencryptedsize);
  memset(iv, 0, sizeof(unsigned char) * ATCHOPS_IV_BUFFER_SIZE);

  // 1c. pkam private key
  ret = atchops_base64_decode((unsigned char *)aespkamprivatekeystr, aespkamprivatekeylen, rsakeyencrypted,
                              rsakeyencryptedsize, &rsakeyencryptedlen);
  if (ret != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "tried base64 decoding pkam private key: %d\n", ret);
    goto exit;
  }

  ret = atchops_aesctr_decrypt(selfencryptionkey, ATCHOPS_AES_256, iv, rsakeyencrypted, rsakeyencryptedlen,
                               (unsigned char *) atkeys->pkamprivatekeystr.str, atkeys->pkamprivatekeystr.size,
                               &(atkeys->pkamprivatekeystr.len));
  if (ret != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR,
                          "atchops_aesctr_decrypt: %d | failed to decrypt pkam private key\n", ret);
    goto exit;
  }

  memset(rsakeyencrypted, 0, sizeof(unsigned char) * rsakeyencryptedsize);
  memset(iv, 0, sizeof(unsigned char) * ATCHOPS_IV_BUFFER_SIZE);

  // 1d. encrypt public key
  ret = atchops_base64_decode((unsigned char *)aesencryptpublickeystr, aesencryptpublickeylen, rsakeyencrypted,
                              rsakeyencryptedsize, &rsakeyencryptedlen);
  if (ret != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "tried base64 decoding encrypt public key: %d\n", ret);
    goto exit;
  }

  ret = atchops_aesctr_decrypt(selfencryptionkey, ATCHOPS_AES_256, iv, rsakeyencrypted, rsakeyencryptedlen, (unsigned char *) atkeys->encryptpublickeystr.str, atkeys->encryptpublickeystr.size,
                               &(atkeys->encryptpublickeystr.len));
  if (ret != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR,
                          "atchops_aesctr_decrypt: %d | failed to decrypt encrypt public key\n", ret);
    goto exit;
  }

  memset(rsakeyencrypted, 0, sizeof(unsigned char) * rsakeyencryptedsize);
  memset(iv, 0, sizeof(unsigned char) * ATCHOPS_IV_BUFFER_SIZE);

  // 1e. encrypt private key
  ret = atchops_base64_decode((unsigned char *)aesencryptprivatekeystr, aesencryptprivatekeylen, rsakeyencrypted,
                              rsakeyencryptedsize, &rsakeyencryptedlen);
  if (ret != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "tried base64 decoding encrypt private key: %d\n", ret);
    goto exit;
  }

  ret = atchops_aesctr_decrypt(selfencryptionkey, ATCHOPS_AES_256, iv, rsakeyencrypted, rsakeyencryptedlen,
                               (unsigned char *) atkeys->encryptprivatekeystr.str, atkeys->encryptprivatekeystr.size,
                               &(atkeys->encryptprivatekeystr.len));
  if (ret != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR,
                          "atchops_aesctr_decrypt: %d | failed to decrypt encrypt private key\n", ret);
    goto exit;
  }

  // 2. populate rsa structs in atkeys struct (4 keys)

  // 2a. pkam public key
  ret = atchops_rsakey_populate_publickey(&(atkeys->pkampublickey), atkeys->pkampublickeystr.str,
                                          atkeys->pkampublickeystr.len);
  if (ret != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR,
                          "atchops_rsakey_populate_publickey: %d | failed to populate pkam public key\n", ret);
    goto exit;
  }

  // 2b. pkam private key
  ret = atchops_rsakey_populate_privatekey(&(atkeys->pkamprivatekey), atkeys->pkamprivatekeystr.str,
                                           atkeys->pkamprivatekeystr.len);
  if (ret != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR,
                          "atchops_rsakey_populate_privatekey: %d | failed to populate pkam private key\n", ret);
    goto exit;
  }

  // 2c. encrypt public key
  ret = atchops_rsakey_populate_privatekey(&(atkeys->encryptprivatekey), atkeys->encryptprivatekeystr.str,
                                           atkeys->encryptprivatekeystr.len);
  if (ret != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR,
                          "atchops_rsakey_populate_privatekey: %d | failed to populate encrypt private key\n", ret);
    goto exit;
  }

  // 2d. encrypt private key
  ret = atchops_rsakey_populate_publickey(&(atkeys->encryptpublickey), atkeys->encryptpublickeystr.str,
                                          atkeys->encryptpublickeystr.len);
  if (ret != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR,
                          "atchops_rsakey_populate_publickey: %d | failed to populate encrypt public key\n", ret);
    goto exit;
  }

  goto exit;

exit: {
  return ret;
}
}

int atclient_atkeys_populate_from_atkeysfile(atclient_atkeys *atkeys, const atclient_atkeysfile atkeysfile) {
  int ret = 1;

  ret = atclient_atkeys_populate_from_strings(
      atkeys, atkeysfile.aespkampublickeystr.str, atkeysfile.aespkampublickeystr.len,
      atkeysfile.aespkamprivatekeystr.str, atkeysfile.aespkamprivatekeystr.len,
      atkeysfile.aesencryptpublickeystr.str, atkeysfile.aesencryptpublickeystr.len,
      atkeysfile.aesencryptprivatekeystr.str, atkeysfile.aesencryptprivatekeystr.len,
      atkeysfile.selfencryptionkeystr.str, atkeysfile.selfencryptionkeystr.len)
    ;
  if (ret != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR,
                          "atclient_atkeys_populate_from_strings: %d | failed to populate from strings\n", ret);
    goto exit;
  }

  goto exit;

exit: { return ret; }
}

int atclient_atkeys_populate_from_path(atclient_atkeys *atkeys, const char *path) {
  int ret = 1;

  atclient_atkeysfile atkeysfile;
  atclient_atkeysfile_init(&atkeysfile);

  ret = atclient_atkeysfile_read(&atkeysfile, path);
  if (ret != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR,
                          "atclient_atkeysfile_read: %d | failed to read file at path: %s\n", ret, path);
    goto exit;
  }

  ret = atclient_atkeys_populate_from_atkeysfile(atkeys, atkeysfile);
  if (ret != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR,
                          "atclient_atkeys_populate_from_atkeysfile: %d | failed to decrypt & populate struct \n", ret);
    goto exit;
  }

  goto exit;
exit: {
  atclient_atkeysfile_free(&atkeysfile);
  return ret;
}
}

void atclient_atkeys_free(atclient_atkeys *atkeys) {
  atclient_atstr_free(&(atkeys->pkampublickeystr));
  atchops_rsakey_publickey_free(&(atkeys->pkampublickey));
  atclient_atstr_free(&(atkeys->pkamprivatekeystr));
  atchops_rsakey_privatekey_free(&(atkeys->pkamprivatekey));
  atclient_atstr_free(&(atkeys->encryptpublickeystr));
  atchops_rsakey_publickey_free(&(atkeys->encryptpublickey));
  atclient_atstr_free(&(atkeys->encryptprivatekeystr));
  atchops_rsakey_privatekey_free(&(atkeys->encryptprivatekey));
  atclient_atstr_free(&(atkeys->selfencryptionkeystr));
}
