#include "atclient/atkeysfile.h"
#include "atlogger/atlogger.h"
#include <cJSON.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// represents buffer size of reading the entire atKeys file
#define FILE_READ_BUFFER_SIZE 8192

#define TAG "atkeysfile"

static bool is_aes_pkam_public_key_str_initialized(atclient_atkeysfile *atkeysfile);
static bool is_aes_pkam_private_key_str_initialized(atclient_atkeysfile *atkeysfile);
static bool is_aes_encrypt_public_key_str_initialized(atclient_atkeysfile *atkeysfile);
static bool is_aes_encrypt_private_key_str_initialized(atclient_atkeysfile *atkeysfile);
static bool is_self_encryption_key_str_initialized(atclient_atkeysfile *atkeysfile);

static void set_aes_pkam_public_key_str_initialized(atclient_atkeysfile *atkeysfile, const bool initialized);
static void set_aes_pkam_private_key_str_initialized(atclient_atkeysfile *atkeysfile, const bool initialized);
static void set_aes_encrypt_public_key_str_initialized(atclient_atkeysfile *atkeysfile, const bool initialized);
static void set_aes_encrypt_private_key_str_initialized(atclient_atkeysfile *atkeysfile, const bool initialized);
static void set_self_encryption_key_str_initialized(atclient_atkeysfile *atkeysfile, const bool initialized);

static void unset_aes_pkam_public_key_str(atclient_atkeysfile *atkeysfile);
static void unset_aes_pkam_private_key_str(atclient_atkeysfile *atkeysfile);
static void unset_aes_encrypt_public_key_str(atclient_atkeysfile *atkeysfile);
static void unset_aes_encrypt_private_key_str(atclient_atkeysfile *atkeysfile);
static void unset_self_encryption_key_str(atclient_atkeysfile *atkeysfile);

static int set_aes_pkam_public_key_str(atclient_atkeysfile *atkeysfile, const char *aes_pkam_public_key_str,
                                   const size_t aes_pkam_publickey_str_len);
static int set_aes_pkam_private_key_str(atclient_atkeysfile *atkeysfile, const char *aes_pkam_private_key_str,
                                    const size_t aes_pkam_private_key_str_len);
static int set_aes_encrypt_public_key_str(atclient_atkeysfile *atkeysfile, const char *aes_encrypt_public_key_str,
                                      const size_t aes_encrypt_public_key_str_len);
static int set_aes_encrypt_private_key_str(atclient_atkeysfile *atkeysfile, const char *aes_encrypt_private_key_str,
                                       const size_t aes_encrypt_private_key_str_len);
static int set_self_encryption_key_str(atclient_atkeysfile *atkeysfile, const char *self_encryption_key_str,
                                    const size_t self_encryption_key_str_len);

void atclient_atkeysfile_init(atclient_atkeysfile *atkeysfile) { memset(atkeysfile, 0, sizeof(atclient_atkeysfile)); }

int atclient_atkeysfile_read(atclient_atkeysfile *atkeysfile, const char *path) {
  int ret = 1;

  unsigned char readbuf[FILE_READ_BUFFER_SIZE];
  memset(readbuf, 0, FILE_READ_BUFFER_SIZE);

  cJSON *root = NULL;

  FILE *file = fopen(path, "r");
  if (file == NULL) {
    ret = 1;
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "fopen failed\n");
    goto exit;
  }

  const size_t bytes_read = fread(readbuf, 1, FILE_READ_BUFFER_SIZE, file);
  fclose(file);
  if (bytes_read == 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "fread failed\n");
    ret = 1;
    goto exit;
  }

  root = cJSON_Parse(readbuf);
  cJSON *aes_pkam_public_key = cJSON_GetObjectItem(root, "aesPkamPublicKey");
  cJSON *aes_pkam_private_key = cJSON_GetObjectItem(root, "aesPkamPrivateKey");
  cJSON *aes_encrypt_public_key = cJSON_GetObjectItem(root, "aesEncryptPublicKey");
  cJSON *aes_encrypt_private_key = cJSON_GetObjectItem(root, "aesEncryptPrivateKey");
  cJSON *self_encryption_key = cJSON_GetObjectItem(root, "selfEncryptionKey");

  if (aes_pkam_private_key == NULL) {
    ret = 1;
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "Error reading aesPkamPrivateKey!\n");
    goto exit;
  }

  if (aes_pkam_public_key == NULL) {
    ret = 1;
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "Error reading aesPkamPublicKey!\n");
    goto exit;
  }

  if (aes_encrypt_private_key == NULL) {
    ret = 1;
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "Error reading aesEncryptPrivateKey!\n");
    goto exit;
  }

  if (aes_encrypt_public_key == NULL) {
    ret = 1;
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "Error reading aesEncryptPublicKey!\n");
    goto exit;
  }

  if (self_encryption_key == NULL) {
    ret = 1;
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "Error reading selfEncryptionKey!\n");
    goto exit;
  }

  if ((ret = set_aes_pkam_public_key_str(atkeysfile, aes_pkam_public_key->valuestring,
                                     strlen(aes_pkam_public_key->valuestring))) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "set_aes_pkam_public_key_str: %d | failed to set aes_pkam_public_key_str\n",
                 ret);
    goto exit;
  }

  if ((ret = set_aes_pkam_private_key_str(atkeysfile, aes_pkam_private_key->valuestring,
                                      strlen(aes_pkam_private_key->valuestring))) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR,
                 "set_aes_pkam_private_key_str: %d | failed to set aes_pkam_private_key_str\n", ret);
    goto exit;
  }

  if ((ret = set_aes_encrypt_public_key_str(atkeysfile, aes_encrypt_public_key->valuestring,
                                        strlen(aes_encrypt_public_key->valuestring))) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR,
                 "set_aes_encrypt_public_key_str: %d | failed to set aes_encrypt_public_key_str\n", ret);
    goto exit;
  }

  if ((ret = set_aes_encrypt_private_key_str(atkeysfile, aes_encrypt_private_key->valuestring,
                                         strlen(aes_encrypt_private_key->valuestring))) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR,
                 "set_aes_encrypt_private_key_str: %d | failed to set aes_encrypt_private_key_str\n", ret);
    goto exit;
  }

  if ((ret = set_self_encryption_key_str(atkeysfile, self_encryption_key->valuestring,
                                      strlen(self_encryption_key->valuestring))) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR,
                 "set_self_encryption_key_str: %d | failed to set self_encryption_key_str\n", ret);
    goto exit;
  }

  ret = 0;
  goto exit;

exit: {
  cJSON_Delete(root);
  return ret;
}
}

void atclient_atkeysfile_free(atclient_atkeysfile *atkeysfile) {
  unset_aes_pkam_public_key_str(atkeysfile);
  unset_aes_pkam_private_key_str(atkeysfile);
  unset_aes_encrypt_public_key_str(atkeysfile);
  unset_aes_encrypt_private_key_str(atkeysfile);
  unset_self_encryption_key_str(atkeysfile);
}

static bool is_aes_pkam_public_key_str_initialized(atclient_atkeysfile *atkeysfile) {
  return atkeysfile->_initialized_fields[ATCLIENT_ATKEYSFILE_AES_PKAM_PUBLIC_KEY_STR_INDEX] & ATCLIENT_ATKEYSFILE_AES_PKAM_PUBLIC_KEY_STR_INITIALIZED;
}

static bool is_aes_pkam_private_key_str_initialized(atclient_atkeysfile *atkeysfile) {
  return atkeysfile->_initialized_fields[ATCLIENT_ATKEYSFILE_AES_PKAM_PRIVATE_KEY_STR_INDEX] & ATCLIENT_ATKEYSFILE_AES_PKAM_PRIVATE_KEY_STR_INITIALIZED;
}

static bool is_aes_encrypt_public_key_str_initialized(atclient_atkeysfile *atkeysfile) {
  return atkeysfile->_initialized_fields[ATCLIENT_ATKEYSFILE_AES_ENCRYPT_PUBLIC_KEY_STR_INDEX] & ATCLIENT_ATKEYSFILE_AES_ENCRYPT_PUBLIC_KEY_STR_INITIALIZED;
}

static bool is_aes_encrypt_private_key_str_initialized(atclient_atkeysfile *atkeysfile) {
  return atkeysfile->_initialized_fields[ATCLIENT_ATKEYSFILE_AES_ENCRYPT_PRIVATE_KEY_STR_INDEX] & ATCLIENT_ATKEYSFILE_AES_ENCRYPT_PRIVATE_KEY_STR_INITIALIZED;
}

static bool is_self_encryption_key_str_initialized(atclient_atkeysfile *atkeysfile) {
  return atkeysfile->_initialized_fields[ATCLIENT_ATKEYSFILE_SELF_ENCRYPTION_KEY_STR_INDEX] & ATCLIENT_ATKEYSFILE_SELF_ENCRYPTION_KEY_STR_INITIALIZED;
}

static void set_aes_pkam_public_key_str_initialized(atclient_atkeysfile *atkeysfile, const bool initialized) {
  if (initialized) {
    atkeysfile->_initialized_fields[ATCLIENT_ATKEYSFILE_AES_PKAM_PUBLIC_KEY_STR_INDEX] |= ATCLIENT_ATKEYSFILE_AES_PKAM_PUBLIC_KEY_STR_INITIALIZED;
  } else {
    atkeysfile->_initialized_fields[ATCLIENT_ATKEYSFILE_AES_PKAM_PUBLIC_KEY_STR_INDEX] &= ~ATCLIENT_ATKEYSFILE_AES_PKAM_PUBLIC_KEY_STR_INITIALIZED;
  }
}

static void set_aes_pkam_private_key_str_initialized(atclient_atkeysfile *atkeysfile, const bool initialized) {
  if (initialized) {
    atkeysfile->_initialized_fields[ATCLIENT_ATKEYSFILE_AES_PKAM_PRIVATE_KEY_STR_INDEX] |= ATCLIENT_ATKEYSFILE_AES_PKAM_PRIVATE_KEY_STR_INITIALIZED;
  } else {
    atkeysfile->_initialized_fields[ATCLIENT_ATKEYSFILE_AES_PKAM_PRIVATE_KEY_STR_INDEX] &= ~ATCLIENT_ATKEYSFILE_AES_PKAM_PRIVATE_KEY_STR_INITIALIZED;
  }
}

static void set_aes_encrypt_public_key_str_initialized(atclient_atkeysfile *atkeysfile, const bool initialized) {
  if (initialized) {
    atkeysfile->_initialized_fields[ATCLIENT_ATKEYSFILE_AES_ENCRYPT_PUBLIC_KEY_STR_INDEX] |= ATCLIENT_ATKEYSFILE_AES_ENCRYPT_PUBLIC_KEY_STR_INITIALIZED;
  } else {
    atkeysfile->_initialized_fields[ATCLIENT_ATKEYSFILE_AES_ENCRYPT_PUBLIC_KEY_STR_INDEX] &= ~ATCLIENT_ATKEYSFILE_AES_ENCRYPT_PUBLIC_KEY_STR_INITIALIZED;
  }
}

static void set_aes_encrypt_private_key_str_initialized(atclient_atkeysfile *atkeysfile, const bool initialized) {
  if (initialized) {
    atkeysfile->_initialized_fields[ATCLIENT_ATKEYSFILE_AES_ENCRYPT_PRIVATE_KEY_STR_INDEX] |= ATCLIENT_ATKEYSFILE_AES_ENCRYPT_PRIVATE_KEY_STR_INITIALIZED;
  } else {
    atkeysfile->_initialized_fields[ATCLIENT_ATKEYSFILE_AES_ENCRYPT_PRIVATE_KEY_STR_INDEX] &= ~ATCLIENT_ATKEYSFILE_AES_ENCRYPT_PRIVATE_KEY_STR_INITIALIZED;
  }
}

static void set_self_encryption_key_str_initialized(atclient_atkeysfile *atkeysfile, const bool initialized) {
  if (initialized) {
    atkeysfile->_initialized_fields[ATCLIENT_ATKEYSFILE_SELF_ENCRYPTION_KEY_STR_INDEX] |= ATCLIENT_ATKEYSFILE_SELF_ENCRYPTION_KEY_STR_INITIALIZED;
  } else {
    atkeysfile->_initialized_fields[ATCLIENT_ATKEYSFILE_SELF_ENCRYPTION_KEY_STR_INDEX] &= ~ATCLIENT_ATKEYSFILE_SELF_ENCRYPTION_KEY_STR_INITIALIZED;
  }
}

static void unset_aes_pkam_public_key_str(atclient_atkeysfile *atkeysfile) {
  if (is_aes_pkam_public_key_str_initialized(atkeysfile)) {
    free(atkeysfile->aes_pkam_public_key_str);
  }
  atkeysfile->aes_pkam_public_key_str = NULL;
  set_aes_pkam_public_key_str_initialized(atkeysfile, false);
}

static void unset_aes_pkam_private_key_str(atclient_atkeysfile *atkeysfile) {
  if (is_aes_pkam_private_key_str_initialized(atkeysfile)) {
    free(atkeysfile->aes_pkam_private_key_str);
  }
  atkeysfile->aes_pkam_private_key_str = NULL;
  set_aes_pkam_private_key_str_initialized(atkeysfile, false);
}

static void unset_aes_encrypt_public_key_str(atclient_atkeysfile *atkeysfile) {
  if (is_aes_encrypt_public_key_str_initialized(atkeysfile)) {
    free(atkeysfile->aes_encrypt_public_key_str);
  }
  atkeysfile->aes_encrypt_public_key_str = NULL;
  set_aes_encrypt_public_key_str_initialized(atkeysfile, false);
}

static void unset_aes_encrypt_private_key_str(atclient_atkeysfile *atkeysfile) {
  if (is_aes_encrypt_private_key_str_initialized(atkeysfile)) {
    free(atkeysfile->aes_encrypt_private_key_str);
  }
  atkeysfile->aes_encrypt_private_key_str = NULL;
  set_aes_encrypt_private_key_str_initialized(atkeysfile, false);
}

static void unset_self_encryption_key_str(atclient_atkeysfile *atkeysfile) {
  if (is_self_encryption_key_str_initialized(atkeysfile)) {
    free(atkeysfile->self_encryption_key_str);
  }
  atkeysfile->self_encryption_key_str = NULL;
  set_self_encryption_key_str_initialized(atkeysfile, false);
}

static int set_aes_pkam_public_key_str(atclient_atkeysfile *atkeysfile, const char *aes_pkam_public_key_str,
                                   const size_t aes_pkam_publickey_str_len) {
  int ret = 1;

  if (is_aes_pkam_public_key_str_initialized(atkeysfile)) {
    unset_aes_pkam_public_key_str(atkeysfile);
  }

  const size_t aes_pkam_public_key_str_size = aes_pkam_publickey_str_len + 1;
  if ((atkeysfile->aes_pkam_public_key_str = (char *)malloc(sizeof(char) * aes_pkam_public_key_str_size)) == NULL) {
    ret = 1;
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "malloc failed\n");
    goto exit;
  }

  set_aes_pkam_public_key_str_initialized(atkeysfile, true);
  memcpy(atkeysfile->aes_pkam_public_key_str, aes_pkam_public_key_str, aes_pkam_publickey_str_len);
  atkeysfile->aes_pkam_public_key_str[aes_pkam_publickey_str_len] = '\0';

  ret = 0;
  goto exit;
exit: { return ret; }
}

static int set_aes_pkam_private_key_str(atclient_atkeysfile *atkeysfile, const char *aes_pkam_private_key_str,
                                    const size_t aes_pkam_private_key_str_len) {
  int ret = 1;

  if (is_aes_pkam_private_key_str_initialized(atkeysfile)) {
    unset_aes_pkam_private_key_str(atkeysfile);
  }

  const size_t aes_pkam_private_key_str_size = aes_pkam_private_key_str_len + 1;
  if ((atkeysfile->aes_pkam_private_key_str = (char *)malloc(sizeof(char) * aes_pkam_private_key_str_size)) == NULL) {
    ret = 1;
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "malloc failed\n");
    goto exit;
  }

  set_aes_pkam_private_key_str_initialized(atkeysfile, true);
  memcpy(atkeysfile->aes_pkam_private_key_str, aes_pkam_private_key_str, aes_pkam_private_key_str_len);
  atkeysfile->aes_pkam_private_key_str[aes_pkam_private_key_str_len] = '\0';

  ret = 0;
  goto exit;
exit: { return ret; }
}
static int set_aes_encrypt_public_key_str(atclient_atkeysfile *atkeysfile, const char *aes_encrypt_public_key_str,
                                      const size_t aes_encrypt_public_key_str_len) {
  int ret = 1;

  if (is_aes_encrypt_public_key_str_initialized(atkeysfile)) {
    unset_aes_encrypt_public_key_str(atkeysfile);
  }

  const size_t aes_encrypt_public_key_str_size = aes_encrypt_public_key_str_len + 1;
  if ((atkeysfile->aes_encrypt_public_key_str = (char *)malloc(sizeof(char) * aes_encrypt_public_key_str_size)) == NULL) {
    ret = 1;
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "malloc failed\n");
    goto exit;
  }

  set_aes_encrypt_public_key_str_initialized(atkeysfile, true);
  memcpy(atkeysfile->aes_encrypt_public_key_str, aes_encrypt_public_key_str, aes_encrypt_public_key_str_len);
  atkeysfile->aes_encrypt_public_key_str[aes_encrypt_public_key_str_len] = '\0';

  ret = 0;
  goto exit;

exit: { return ret; }
}

static int set_aes_encrypt_private_key_str(atclient_atkeysfile *atkeysfile, const char *aes_encrypt_private_key_str,
                                       const size_t aes_encrypt_private_key_str_len) {
  int ret = 1;

  if (is_aes_encrypt_private_key_str_initialized(atkeysfile)) {
    unset_aes_encrypt_private_key_str(atkeysfile);
  }

  const size_t aes_encrypt_private_key_str_size = aes_encrypt_private_key_str_len + 1;
  if ((atkeysfile->aes_encrypt_private_key_str = (char *)malloc(sizeof(char) * aes_encrypt_private_key_str_size)) == NULL) {
    ret = 1;
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "malloc failed\n");
    goto exit;
  }

  set_aes_encrypt_private_key_str_initialized(atkeysfile, true);
  memcpy(atkeysfile->aes_encrypt_private_key_str, aes_encrypt_private_key_str, aes_encrypt_private_key_str_len);
  atkeysfile->aes_encrypt_private_key_str[aes_encrypt_private_key_str_len] = '\0';

  ret = 0;
  goto exit;
exit: { return ret; }
}

static int set_self_encryption_key_str(atclient_atkeysfile *atkeysfile, const char *self_encryption_key_str,
                                    const size_t self_encryption_key_str_len) {
  int ret = 1;

  if (is_self_encryption_key_str_initialized(atkeysfile)) {
    unset_self_encryption_key_str(atkeysfile);
  }

  const size_t selfencryptionkeystrsize = self_encryption_key_str_len + 1;
  if ((atkeysfile->self_encryption_key_str = (char *)malloc(sizeof(char) * selfencryptionkeystrsize)) == NULL) {
    ret = 1;
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "malloc failed\n");
    goto exit;
  }

  set_self_encryption_key_str_initialized(atkeysfile, true);
  memcpy(atkeysfile->self_encryption_key_str, self_encryption_key_str, self_encryption_key_str_len);
  atkeysfile->self_encryption_key_str[self_encryption_key_str_len] = '\0';

  ret = 0;
  goto exit;

exit: { return ret; }
}
