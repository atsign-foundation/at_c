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

#define TAG "atkeys"

static bool is_pkampublickeybase64_initialized(atclient_atkeys *atkeys);
static bool is_pkamprivatekeybase64_initialized(atclient_atkeys *atkeys);
static bool is_encryptpublickeybase64_initialized(atclient_atkeys *atkeys);
static bool is_encryptprivatekeybase64_initialized(atclient_atkeys *atkeys);
static bool is_selfencryptionkeybase64_initialized(atclient_atkeys *atkeys);

static void set_pkampublickeybase64_initialized(atclient_atkeys *atkeys, const bool initialized);
static void set_pkamprivatekeybase64_initialized(atclient_atkeys *atkeys, const bool initialized);
static void set_encryptpublickeybase64_initialized(atclient_atkeys *atkeys, const bool initialized);
static void set_encryptprivatekeybase64_initialized(atclient_atkeys *atkeys, const bool initialized);
static void set_selfencryptionkeybase64_initialized(atclient_atkeys *atkeys, const bool initialized);

static void unset_pkampublickeybase64(atclient_atkeys *atkeys);
static void unset_pkamprivatekeybase64(atclient_atkeys *atkeys);
static void unset_encryptpublickeybase64(atclient_atkeys *atkeys);
static void unset_encryptprivatekeybase64(atclient_atkeys *atkeys);
static void unset_selfencryptionkeybase64(atclient_atkeys *atkeys);

static int set_pkampublickeybase64(atclient_atkeys *atkeys, const char *pkampublickeybase64,
                                   const size_t pkampublickeylen);
static int set_pkamprivatekeybase64(atclient_atkeys *atkeys, const char *pkamprivatekeybase64,
                                    const size_t pkamprivatekeylen);
static int set_encryptpublickeybase64(atclient_atkeys *atkeys, const char *encryptpublickeybase64,
                                      const size_t encryptpublickeylen);
static int set_encryptprivatekeybase64(atclient_atkeys *atkeys, const char *encryptprivatekeybase64,
                                       const size_t encryptprivatekeylen);
static int set_selfencryptionkeybase64(atclient_atkeys *atkeys, const char *selfencryptionkeybase64,
                                       const size_t selfencryptionkeylen);

void atclient_atkeys_init(atclient_atkeys *atkeys) {
  memset(atkeys, 0, sizeof(atclient_atkeys));
  atchops_rsakey_publickey_init(&(atkeys->pkampublickey));
  atchops_rsakey_privatekey_init(&(atkeys->pkamprivatekey));
  atchops_rsakey_publickey_init(&(atkeys->encryptpublickey));
  atchops_rsakey_privatekey_init(&(atkeys->encryptprivatekey));
}

void atclient_atkeys_free(atclient_atkeys *atkeys) {
  atchops_rsakey_publickey_free(&(atkeys->pkampublickey));
  atchops_rsakey_privatekey_free(&(atkeys->pkamprivatekey));
  atchops_rsakey_publickey_free(&(atkeys->encryptpublickey));
  atchops_rsakey_privatekey_free(&(atkeys->encryptprivatekey));
}

int atclient_atkeys_populate_from_strings(atclient_atkeys *atkeys, const char *aespkampublickeystr,
                                          const size_t aespkampublickeylen, const char *aespkamprivatekeystr,
                                          const size_t aespkamprivatekeylen, const char *aesencryptpublickeystr,
                                          const size_t aesencryptpublickeylen, const char *aesencryptprivatekeystr,
                                          const size_t aesencryptprivatekeylen, const char *selfencryptionkeystr,
                                          const size_t selfencryptionkeystrlen) {
  int ret = 1;

  /*
   * 1. Validate arguments
   */

  if (atkeys == NULL) {
    ret = 1;
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atkeys is NULL\n");
    return ret;
  }

  if (aespkampublickeystr == NULL) {
    ret = 1;
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "aespkampublickeystr is NULL\n");
    return ret;
  }

  if (aespkamprivatekeystr == NULL) {
    ret = 1;
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "aespkamprivatekeystr is NULL\n");
    return ret;
  }

  if (aesencryptpublickeystr == NULL) {
    ret = 1;
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "aesencryptpublickeystr is NULL\n");
    return ret;
  }

  if (aesencryptprivatekeystr == NULL) {
    ret = 1;
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "aesencryptprivatekeystr is NULL\n");
    return ret;
  }

  if (selfencryptionkeystr == NULL) {
    ret = 1;
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "selfencryptionkeystr is NULL\n");
    return ret;
  }

  if (aespkampublickeylen == 0) {
    ret = 1;
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "aespkampublickeylen is 0\n");
    return ret;
  }

  if (aespkamprivatekeylen == 0) {
    ret = 1;
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "aespkamprivatekeylen is 0\n");
    return ret;
  }

  if (aesencryptpublickeylen == 0) {
    ret = 1;
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "aesencryptpublickeylen is 0\n");
    return ret;
  }

  if (aesencryptprivatekeylen == 0) {
    ret = 1;
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "aesencryptprivatekeylen is 0\n");
    return ret;
  }

  if (selfencryptionkeystrlen == 0) {
    ret = 1;
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "selfencryptionkeystrlen is 0\n");
    return ret;
  }

  /*
   * 2. Initialize variables
   */

  // 2a. Use legacy IV
  // the atKeys are encrypted with bytes of 0s
  unsigned char iv[ATCHOPS_IV_BUFFER_SIZE];
  memset(iv, 0, sizeof(unsigned char) * ATCHOPS_IV_BUFFER_SIZE);

  // holds the base64-decoded non-encrypted self encryption key
  // to use for decrypting the other RSA keys
  const size_t selfencryptionkeysize = ATCHOPS_AES_256 / 8;
  unsigned char selfencryptionkey[selfencryptionkeysize];
  memset(selfencryptionkey, 0, sizeof(unsigned char) * selfencryptionkeysize);
  size_t selfencryptionkeylen = 0;

  // temporarily holds the base64-encoded encrypted RSA key for decryption
  const size_t rsakeyencryptedsize = 4096;
  unsigned char rsakeyencrypted[rsakeyencryptedsize];
  memset(rsakeyencrypted, 0, sizeof(unsigned char) * rsakeyencryptedsize);
  size_t rsakeyencryptedlen = 0;

  // temporarily holds the base64-encoded decrypted RSA key
  const size_t rsakeydecryptedsize = 4096;
  unsigned char rsakeydecrypted[rsakeydecryptedsize];
  memset(rsakeydecrypted, 0, sizeof(unsigned char) * rsakeydecryptedsize);
  size_t rsakeydecryptedlen = 0;

  /*
   * 3. Prepare self encryption key for use
   */
  if ((ret = atchops_base64_decode((unsigned char *)selfencryptionkeystr, selfencryptionkeystrlen, selfencryptionkey,
                                   selfencryptionkeysize, &selfencryptionkeylen)) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "tried base64 decoding selfencryption key: %d\n", ret);
    goto exit;
  }

  /*
   * 4. Decrypt and populate atkeys struct
   */

  // 4a. self encryption key
  if ((ret = set_selfencryptionkeybase64(atkeys, selfencryptionkeystr, selfencryptionkeylen)) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "set_selfencryptionkeybase64: %d | failed to set selfencryptionkeystr\n",
                 ret);
    goto exit;
  }

  // 4b. pkam public key
  if ((ret = atchops_base64_decode((unsigned char *)aespkampublickeystr, aespkampublickeylen, rsakeyencrypted,
                                   rsakeyencryptedsize, &rsakeyencryptedlen)) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "tried base64 decoding pkam public key: %d\n", ret);
    goto exit;
  }

  if ((ret = atchops_aesctr_decrypt(selfencryptionkey, ATCHOPS_AES_256, iv, rsakeyencrypted, rsakeyencryptedlen,
                                    rsakeydecrypted, rsakeydecryptedsize, &rsakeydecryptedlen)) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atchops_aesctr_decrypt: %d | failed to decrypt pkam public key\n",
                 ret);
    goto exit;
  }

  if ((ret = set_pkampublickeybase64(atkeys, (const char *)rsakeydecrypted, rsakeydecryptedlen)) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "set_pkampublickeybase64: %d | failed to set pkampublickeystr\n", ret);
    goto exit;
  }

  memset(rsakeyencrypted, 0, sizeof(unsigned char) * rsakeyencryptedsize);
  memset(rsakeydecrypted, 0, sizeof(unsigned char) * rsakeydecryptedsize);
  memset(iv, 0, sizeof(unsigned char) * ATCHOPS_IV_BUFFER_SIZE);

  // 4c. pkam private key
  if ((ret = atchops_base64_decode((unsigned char *)aespkamprivatekeystr, aespkamprivatekeylen, rsakeyencrypted,
                                   rsakeyencryptedsize, &rsakeyencryptedlen)) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "tried base64 decoding pkam private key: %d\n", ret);
    goto exit;
  }

  if ((ret = atchops_aesctr_decrypt(selfencryptionkey, ATCHOPS_AES_256, iv, rsakeyencrypted, rsakeyencryptedlen,
                                    rsakeydecrypted, rsakeydecryptedsize, &rsakeydecryptedlen)) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atchops_aesctr_decrypt: %d | failed to decrypt pkam private key\n",
                 ret);
    goto exit;
  }

  if ((ret = set_pkamprivatekeybase64(atkeys, (const char *)rsakeydecrypted, rsakeydecryptedlen)) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "set_pkamprivatekeybase64: %d | failed to set pkamprivatekeystr\n", ret);
    goto exit;
  }

  memset(rsakeyencrypted, 0, sizeof(unsigned char) * rsakeyencryptedsize);
  memset(rsakeydecrypted, 0, sizeof(unsigned char) * rsakeydecryptedsize);
  memset(iv, 0, sizeof(unsigned char) * ATCHOPS_IV_BUFFER_SIZE);

  // 4d. encrypt public key
  if ((ret = atchops_base64_decode((unsigned char *)aesencryptpublickeystr, aesencryptpublickeylen, rsakeyencrypted,
                                   rsakeyencryptedsize, &rsakeyencryptedlen)) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "tried base64 decoding encrypt public key: %d\n", ret);
    goto exit;
  }

  if ((ret = atchops_aesctr_decrypt(selfencryptionkey, ATCHOPS_AES_256, iv, rsakeyencrypted, rsakeyencryptedlen,
                                    rsakeydecrypted, rsakeydecryptedsize, &rsakeydecryptedlen)) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR,
                 "atchops_aesctr_decrypt: %d | failed to decrypt encrypt public key\n", ret);
    goto exit;
  }

  if ((ret = set_encryptpublickeybase64(atkeys, (const char *)rsakeydecrypted, rsakeydecryptedlen)) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "set_encryptpublickeybase64: %d | failed to set encryptpublickeystr\n",
                 ret);
    goto exit;
  }

  memset(rsakeyencrypted, 0, sizeof(unsigned char) * rsakeyencryptedsize);
  memset(rsakeydecrypted, 0, sizeof(unsigned char) * rsakeydecryptedsize);
  memset(iv, 0, sizeof(unsigned char) * ATCHOPS_IV_BUFFER_SIZE);

  // 4e. encrypt private key
  if ((ret = atchops_base64_decode((unsigned char *)aesencryptprivatekeystr, aesencryptprivatekeylen, rsakeyencrypted,
                                   rsakeyencryptedsize, &rsakeyencryptedlen)) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "tried base64 decoding encrypt private key: %d\n", ret);
    goto exit;
  }

  if ((ret = atchops_aesctr_decrypt(selfencryptionkey, ATCHOPS_AES_256, iv, rsakeyencrypted, rsakeyencryptedlen,
                                    rsakeydecrypted, rsakeydecryptedsize, &rsakeydecryptedlen)) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR,
                 "atchops_aesctr_decrypt: %d | failed to decrypt encrypt private key\n", ret);
    goto exit;
  }

  if ((ret = set_encryptprivatekeybase64(atkeys, (const char *)rsakeydecrypted, rsakeydecryptedlen)) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "set_encryptprivatekeybase64: %d | failed to set encryptprivatekeystr\n",
                 ret);
    goto exit;
  }

  /*
   * 5. Populate rsakey structs
   */

  // 5a. pkam public key
  if ((ret = atchops_rsakey_populate_publickey(&(atkeys->pkampublickey), atkeys->pkampublickeybase64,
                                               strlen(atkeys->pkampublickeybase64))) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR,
                 "atchops_rsakey_populate_publickey: %d | failed to populate pkam public key\n", ret);
    goto exit;
  }

  // 5b. pkam private key
  if ((ret = atchops_rsakey_populate_privatekey(&(atkeys->pkamprivatekey), atkeys->pkamprivatekeybase64,
                                                strlen(atkeys->pkamprivatekeybase64))) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR,
                 "atchops_rsakey_populate_privatekey: %d | failed to populate pkam private key\n", ret);
    goto exit;
  }

  // 5c. encrypt public key
  if ((ret = atchops_rsakey_populate_privatekey(&(atkeys->encryptprivatekey), atkeys->encryptprivatekeybase64,
                                                strlen(atkeys->encryptprivatekeybase64))) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR,
                 "atchops_rsakey_populate_privatekey: %d | failed to populate encrypt private key\n", ret);
    goto exit;
  }

  // 5d. encrypt private key
  if ((ret = atchops_rsakey_populate_publickey(&(atkeys->encryptpublickey), atkeys->encryptpublickeybase64,
                                               strlen(atkeys->encryptpublickeybase64))) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR,
                 "atchops_rsakey_populate_publickey: %d | failed to populate encrypt public key\n", ret);
    goto exit;
  }

  ret = 0;
  goto exit;

exit: { return ret; }
}

int atclient_atkeys_populate_from_atkeysfile(atclient_atkeys *atkeys, const atclient_atkeysfile atkeysfile) {
  int ret = 1;

  ret = atclient_atkeys_populate_from_strings(
      atkeys, atkeysfile.aespkampublickeystr, strlen(atkeysfile.aespkampublickeystr),
      atkeysfile.aespkamprivatekeystr, strlen(atkeysfile.aespkamprivatekeystr), atkeysfile.aesencryptpublickeystr,
      strlen(atkeysfile.aesencryptpublickeystr), atkeysfile.aesencryptprivatekeystr,
      strlen(atkeysfile.aesencryptprivatekeystr), atkeysfile.selfencryptionkeystr, strlen(atkeysfile.selfencryptionkeystr));
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
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atclient_atkeysfile_read: %d | failed to read file at path: %s\n",
                 ret, path);
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

static bool is_pkampublickeybase64_initialized(atclient_atkeys *atkeys) {
  return atkeys->_initializedfields[PKAMPUBLICKEY_INDEX] & PKAMPUBLICKEY_INITIALIZED;
}

static bool is_pkamprivatekeybase64_initialized(atclient_atkeys *atkeys) {
  return atkeys->_initializedfields[PKAMPRIVATEKEY_INDEX] & PKAMPRIVATEKEY_INITIALIZED;
}

static bool is_encryptpublickeybase64_initialized(atclient_atkeys *atkeys) {
  return atkeys->_initializedfields[ENCRYPTPUBLICKEY_INDEX] & ENCRYPTPUBLICKEY_INITIALIZED;
}

static bool is_encryptprivatekeybase64_initialized(atclient_atkeys *atkeys) {
  return atkeys->_initializedfields[ENCRYPTPRIVATEKEY_INDEX] & ENCRYPTPRIVATEKEY_INITIALIZED;
}

static bool is_selfencryptionkeybase64_initialized(atclient_atkeys *atkeys) {
  return atkeys->_initializedfields[SELFENCRYPTIONKEY_INDEX] & SELFENCRYPTIONKEY_INITIALIZED;
}

static void set_pkampublickeybase64_initialized(atclient_atkeys *atkeys, const bool initialized) {
  if (initialized) {
    atkeys->_initializedfields[PKAMPUBLICKEY_INDEX] |= PKAMPUBLICKEY_INITIALIZED;
  } else {
    atkeys->_initializedfields[PKAMPUBLICKEY_INDEX] &= ~PKAMPUBLICKEY_INITIALIZED;
  }
}

static void set_pkamprivatekeybase64_initialized(atclient_atkeys *atkeys, const bool initialized) {
  if (initialized) {
    atkeys->_initializedfields[PKAMPRIVATEKEY_INDEX] |= PKAMPRIVATEKEY_INITIALIZED;
  } else {
    atkeys->_initializedfields[PKAMPRIVATEKEY_INDEX] &= ~PKAMPRIVATEKEY_INITIALIZED;
  }
}

static void set_encryptpublickeybase64_initialized(atclient_atkeys *atkeys, const bool initialized) {
  if (initialized) {
    atkeys->_initializedfields[ENCRYPTPUBLICKEY_INDEX] |= ENCRYPTPUBLICKEY_INITIALIZED;
  } else {
    atkeys->_initializedfields[ENCRYPTPUBLICKEY_INDEX] &= ~ENCRYPTPUBLICKEY_INITIALIZED;
  }
}

static void set_encryptprivatekeybase64_initialized(atclient_atkeys *atkeys, const bool initialized) {
  if (initialized) {
    atkeys->_initializedfields[ENCRYPTPRIVATEKEY_INDEX] |= ENCRYPTPRIVATEKEY_INITIALIZED;
  } else {
    atkeys->_initializedfields[ENCRYPTPRIVATEKEY_INDEX] &= ~ENCRYPTPRIVATEKEY_INITIALIZED;
  }
}

static void set_selfencryptionkeybase64_initialized(atclient_atkeys *atkeys, const bool initialized) {
  if (initialized) {
    atkeys->_initializedfields[SELFENCRYPTIONKEY_INDEX] |= SELFENCRYPTIONKEY_INITIALIZED;
  } else {
    atkeys->_initializedfields[SELFENCRYPTIONKEY_INDEX] &= ~SELFENCRYPTIONKEY_INITIALIZED;
  }
}

static void unset_pkampublickeybase64(atclient_atkeys *atkeys) {
  if (is_pkampublickeybase64_initialized(atkeys)) {
    free(atkeys->pkampublickeybase64);
  }
  atkeys->pkampublickeybase64 = NULL;
  set_pkampublickeybase64_initialized(atkeys, false);
}

static void unset_pkamprivatekeybase64(atclient_atkeys *atkeys) {
  if (is_pkamprivatekeybase64_initialized(atkeys)) {
    free(atkeys->pkamprivatekeybase64);
  }
  atkeys->pkamprivatekeybase64 = NULL;
  set_pkamprivatekeybase64_initialized(atkeys, false);
}

static void unset_encryptpublickeybase64(atclient_atkeys *atkeys) {
  if (is_encryptpublickeybase64_initialized(atkeys)) {
    free(atkeys->encryptpublickeybase64);
  }
  atkeys->encryptpublickeybase64 = NULL;
  set_encryptpublickeybase64_initialized(atkeys, false);
}

static void unset_encryptprivatekeybase64(atclient_atkeys *atkeys) {
  if (is_encryptprivatekeybase64_initialized(atkeys)) {
    free(atkeys->encryptprivatekeybase64);
  }
  atkeys->encryptprivatekeybase64 = NULL;
  set_encryptprivatekeybase64_initialized(atkeys, false);
}

static void unset_selfencryptionkeybase64(atclient_atkeys *atkeys) {
  if (is_selfencryptionkeybase64_initialized(atkeys)) {
    free(atkeys->selfencryptionkeybase64);
  }
  atkeys->selfencryptionkeybase64 = NULL;
  set_selfencryptionkeybase64_initialized(atkeys, false);
}

static int set_pkampublickeybase64(atclient_atkeys *atkeys, const char *pkampublickeybase64,
                                   const size_t pkampublickeylen) {
  int ret = 1;

  if (is_pkampublickeybase64_initialized(atkeys)) {
    unset_pkampublickeybase64(atkeys);
  }

  const size_t pkampublickeysize = pkampublickeylen + 1;
  atkeys->pkampublickeybase64 = (char *)malloc(sizeof(char) * (pkampublickeysize));
  if (atkeys->pkampublickeybase64 == NULL) {
    ret = 1;
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "malloc: %d | failed to allocate memory for pkampublickeybase64\n",
                 ret);
    goto exit;
  }

  memcpy(atkeys->pkampublickeybase64, pkampublickeybase64, pkampublickeylen);
  atkeys->pkampublickeybase64[pkampublickeylen] = '\0';

  set_pkampublickeybase64_initialized(atkeys, true);

  ret = 0;
  goto exit;

exit: { return ret; }
}

static int set_pkamprivatekeybase64(atclient_atkeys *atkeys, const char *pkamprivatekeybase64,
                                    const size_t pkamprivatekeylen) {
  int ret = 1;

  if (is_pkamprivatekeybase64_initialized(atkeys)) {
    unset_pkamprivatekeybase64(atkeys);
  }

  const size_t pkamprivatekeysize = pkamprivatekeylen + 1;
  atkeys->pkamprivatekeybase64 = (char *)malloc(sizeof(char) * (pkamprivatekeysize));
  if (atkeys->pkamprivatekeybase64 == NULL) {
    ret = 1;
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "malloc: %d | failed to allocate memory for pkamprivatekeybase64\n",
                 ret);
    goto exit;
  }

  memcpy(atkeys->pkamprivatekeybase64, pkamprivatekeybase64, pkamprivatekeylen);
  atkeys->pkamprivatekeybase64[pkamprivatekeylen] = '\0';

  set_pkamprivatekeybase64_initialized(atkeys, true);

  ret = 0;
  goto exit;
exit: { return ret; }
}

static int set_encryptpublickeybase64(atclient_atkeys *atkeys, const char *encryptpublickeybase64,
                                      const size_t encryptpublickeylen) {
  int ret = 1;

  if (is_encryptpublickeybase64_initialized(atkeys)) {
    unset_encryptpublickeybase64(atkeys);
  }

  const size_t encryptpublickeysize = encryptpublickeylen + 1;
  atkeys->encryptpublickeybase64 = (char *)malloc(sizeof(char) * (encryptpublickeysize));
  if (atkeys->encryptpublickeybase64 == NULL) {
    ret = 1;
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR,
                 "malloc: %d | failed to allocate memory for encryptpublickeybase64\n", ret);
    goto exit;
  }

  memcpy(atkeys->encryptpublickeybase64, encryptpublickeybase64, encryptpublickeylen);
  atkeys->encryptpublickeybase64[encryptpublickeylen] = '\0';

  set_encryptpublickeybase64_initialized(atkeys, true);

  ret = 0;
  goto exit;
exit: { return ret; }
}

static int set_encryptprivatekeybase64(atclient_atkeys *atkeys, const char *encryptprivatekeybase64,
                                       const size_t encryptprivatekeylen) {
  int ret = 1;

  if (is_encryptprivatekeybase64_initialized(atkeys)) {
    unset_encryptprivatekeybase64(atkeys);
  }

  const size_t encryptprivatekeysize = encryptprivatekeylen + 1;
  atkeys->encryptprivatekeybase64 = (char *)malloc(sizeof(char) * (encryptprivatekeysize));
  if (atkeys->encryptprivatekeybase64 == NULL) {
    ret = 1;
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR,
                 "malloc: %d | failed to allocate memory for encryptprivatekeybase64\n", ret);
    goto exit;
  }

  memcpy(atkeys->encryptprivatekeybase64, encryptprivatekeybase64, encryptprivatekeylen);
  atkeys->encryptprivatekeybase64[encryptprivatekeylen] = '\0';

  set_encryptprivatekeybase64_initialized(atkeys, true);

  ret = 0;
  goto exit;
exit: { return ret; }
}

static int set_selfencryptionkeybase64(atclient_atkeys *atkeys, const char *selfencryptionkeybase64,
                                       const size_t selfencryptionkeylen) {
  int ret = 1;

  if (is_selfencryptionkeybase64_initialized(atkeys)) {
    unset_selfencryptionkeybase64(atkeys);
  }

  const size_t selfencryptionkeysize = selfencryptionkeylen + 1;
  atkeys->selfencryptionkeybase64 = (char *)malloc(sizeof(char) * (selfencryptionkeysize));
  if (atkeys->selfencryptionkeybase64 == NULL) {
    ret = 1;
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR,
                 "malloc: %d | failed to allocate memory for selfencryptionkeybase64\n", ret);
    goto exit;
  }

  memcpy(atkeys->selfencryptionkeybase64, selfencryptionkeybase64, selfencryptionkeylen);
  atkeys->selfencryptionkeybase64[selfencryptionkeylen] = '\0';

  set_selfencryptionkeybase64_initialized(atkeys, true);

  ret = 0;
  goto exit;
exit: { return ret; }
}
