#include "atclient/atkeys_file.h"
#include "atlogger/atlogger.h"
#include <cJSON.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// represents buffer size of reading the entire atKeys file
#define FILE_READ_BUFFER_SIZE 8192

#define TAG "atkeys_file"

static bool is_aes_pkam_public_key_str_initialized(atclient_atkeys_file *atkeys_file);
static bool is_aes_pkam_private_key_str_initialized(atclient_atkeys_file *atkeys_file);
static bool is_aes_encrypt_public_key_str_initialized(atclient_atkeys_file *atkeys_file);
static bool is_aes_encrypt_private_key_str_initialized(atclient_atkeys_file *atkeys_file);
static bool is_self_encryption_key_str_initialized(atclient_atkeys_file *atkeys_file);

static void set_aes_pkam_public_key_str_initialized(atclient_atkeys_file *atkeys_file, const bool initialized);
static void set_aes_pkam_private_key_str_initialized(atclient_atkeys_file *atkeys_file, const bool initialized);
static void set_aes_encrypt_public_key_str_initialized(atclient_atkeys_file *atkeys_file, const bool initialized);
static void set_aes_encrypt_private_key_str_initialized(atclient_atkeys_file *atkeys_file, const bool initialized);
static void set_self_encryption_key_str_initialized(atclient_atkeys_file *atkeys_file, const bool initialized);

static void unset_aes_pkam_public_key_str(atclient_atkeys_file *atkeys_file);
static void unset_aes_pkam_private_key_str(atclient_atkeys_file *atkeys_file);
static void unset_aes_encrypt_public_key_str(atclient_atkeys_file *atkeys_file);
static void unset_aes_encrypt_private_key_str(atclient_atkeys_file *atkeys_file);
static void unset_self_encryption_key_str(atclient_atkeys_file *atkeys_file);

static int set_aes_pkam_public_key_str(atclient_atkeys_file *atkeys_file, const char *aes_pkam_public_key_str,
                                       const size_t aes_pkam_publickey_str_len);
static int set_aes_pkam_private_key_str(atclient_atkeys_file *atkeys_file, const char *aes_pkam_private_key_str,
                                        const size_t aes_pkam_private_key_str_len);
static int set_aes_encrypt_public_key_str(atclient_atkeys_file *atkeys_file, const char *aes_encrypt_public_key_str,
                                          const size_t aes_encrypt_public_key_str_len);
static int set_aes_encrypt_private_key_str(atclient_atkeys_file *atkeys_file, const char *aes_encrypt_private_key_str,
                                           const size_t aes_encrypt_private_key_str_len);
static int set_self_encryption_key_str(atclient_atkeys_file *atkeys_file, const char *self_encryption_key_str,
                                       const size_t self_encryption_key_str_len);

void atclient_atkeys_file_init(atclient_atkeys_file *atkeys_file) { memset(atkeys_file, 0, sizeof(atclient_atkeys_file)); }

int atclient_atkeys_file_from_path(atclient_atkeys_file *atkeys_file, const char *path) {
    int ret = 1;
    unsigned char readbuf[FILE_READ_BUFFER_SIZE];
    memset(readbuf, 0, FILE_READ_BUFFER_SIZE);

    FILE *file = fopen(path, "r");
    if (file == NULL) {
        atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "fopen failed\n");
        return ret;
    }

    const size_t bytes_read = fread(readbuf, 1, FILE_READ_BUFFER_SIZE, file);
    fclose(file);
    if (bytes_read == 0) {
        atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "fread failed\n");
        return ret;
    }

    ret = atclient_atkeys_file_from_string(atkeys_file, (const char *)readbuf);
    return ret;
}

int atclient_atkeys_file_from_string(atclient_atkeys_file *atkeys_file, const char *file_string) {
  int ret = 1;

  cJSON *root = cJSON_Parse(file_string);
  if (root == NULL) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "cJSON_Parse failed\n");
    return ret;
  }

  cJSON *aes_pkam_public_key = cJSON_GetObjectItem(root, "aesPkamPublicKey");
  cJSON *aes_pkam_private_key = cJSON_GetObjectItem(root, "aesPkamPrivateKey");
  cJSON *aes_encrypt_public_key = cJSON_GetObjectItem(root, "aesEncryptPublicKey");
  cJSON *aes_encrypt_private_key = cJSON_GetObjectItem(root, "aesEncryptPrivateKey");
  cJSON *self_encryption_key = cJSON_GetObjectItem(root, "selfEncryptionKey");

  if (aes_pkam_private_key == NULL || aes_pkam_public_key == NULL || aes_encrypt_private_key == NULL ||
      aes_encrypt_public_key == NULL || self_encryption_key == NULL) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "Error reading keys from JSON!\n");
    goto cleanup;
  }

  if ((ret = set_aes_pkam_public_key_str(atkeys_file, aes_pkam_public_key->valuestring,
                                         strlen(aes_pkam_public_key->valuestring))) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "set_aes_pkam_public_key_str: %d\n", ret);
    goto cleanup;
  }

  if ((ret = set_aes_pkam_private_key_str(atkeys_file, aes_pkam_private_key->valuestring,
                                          strlen(aes_pkam_private_key->valuestring))) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "set_aes_pkam_private_key_str: %d\n", ret);
    goto cleanup;
  }

  if ((ret = set_aes_encrypt_public_key_str(atkeys_file, aes_encrypt_public_key->valuestring,
                                            strlen(aes_encrypt_public_key->valuestring))) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "set_aes_encrypt_public_key_str: %d\n", ret);
    goto cleanup;
  }

  if ((ret = set_aes_encrypt_private_key_str(atkeys_file, aes_encrypt_private_key->valuestring,
                                             strlen(aes_encrypt_private_key->valuestring))) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "set_aes_encrypt_private_key_str: %d\n", ret);
    goto cleanup;
  }

  if ((ret = set_self_encryption_key_str(atkeys_file, self_encryption_key->valuestring,
                                         strlen(self_encryption_key->valuestring))) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "set_self_encryption_key_str: %d\n", ret);
    goto cleanup;
  }

  ret = 0;

cleanup: {
  cJSON_Delete(root);
  return ret;
}
}

void atclient_atkeys_file_free(atclient_atkeys_file *atkeys_file) {
  unset_aes_pkam_public_key_str(atkeys_file);
  unset_aes_pkam_private_key_str(atkeys_file);
  unset_aes_encrypt_public_key_str(atkeys_file);
  unset_aes_encrypt_private_key_str(atkeys_file);
  unset_self_encryption_key_str(atkeys_file);
}

static bool is_aes_pkam_public_key_str_initialized(atclient_atkeys_file *atkeys_file) {
  return atkeys_file->_initialized_fields[ATCLIENT_ATKEYS_FILE_AES_PKAM_PUBLIC_KEY_STR_INDEX] &
         ATCLIENT_ATKEYS_FILE_AES_PKAM_PUBLIC_KEY_STR_INITIALIZED;
}

static bool is_aes_pkam_private_key_str_initialized(atclient_atkeys_file *atkeys_file) {
  return atkeys_file->_initialized_fields[ATCLIENT_ATKEYS_FILE_AES_PKAM_PRIVATE_KEY_STR_INDEX] &
         ATCLIENT_ATKEYS_FILE_AES_PKAM_PRIVATE_KEY_STR_INITIALIZED;
}

static bool is_aes_encrypt_public_key_str_initialized(atclient_atkeys_file *atkeys_file) {
  return atkeys_file->_initialized_fields[ATCLIENT_ATKEYS_FILE_AES_ENCRYPT_PUBLIC_KEY_STR_INDEX] &
         ATCLIENT_ATKEYS_FILE_AES_ENCRYPT_PUBLIC_KEY_STR_INITIALIZED;
}

static bool is_aes_encrypt_private_key_str_initialized(atclient_atkeys_file *atkeys_file) {
  return atkeys_file->_initialized_fields[ATCLIENT_ATKEYS_FILE_AES_ENCRYPT_PRIVATE_KEY_STR_INDEX] &
         ATCLIENT_ATKEYS_FILE_AES_ENCRYPT_PRIVATE_KEY_STR_INITIALIZED;
}

static bool is_self_encryption_key_str_initialized(atclient_atkeys_file *atkeys_file) {
  return atkeys_file->_initialized_fields[ATCLIENT_ATKEYS_FILE_SELF_ENCRYPTION_KEY_STR_INDEX] &
         ATCLIENT_ATKEYS_FILE_SELF_ENCRYPTION_KEY_STR_INITIALIZED;
}

static void set_aes_pkam_public_key_str_initialized(atclient_atkeys_file *atkeys_file, const bool initialized) {
  if (initialized) {
    atkeys_file->_initialized_fields[ATCLIENT_ATKEYS_FILE_AES_PKAM_PUBLIC_KEY_STR_INDEX] |=
        ATCLIENT_ATKEYS_FILE_AES_PKAM_PUBLIC_KEY_STR_INITIALIZED;
  } else {
    atkeys_file->_initialized_fields[ATCLIENT_ATKEYS_FILE_AES_PKAM_PUBLIC_KEY_STR_INDEX] &=
        ~ATCLIENT_ATKEYS_FILE_AES_PKAM_PUBLIC_KEY_STR_INITIALIZED;
  }
}

static void set_aes_pkam_private_key_str_initialized(atclient_atkeys_file *atkeys_file, const bool initialized) {
  if (initialized) {
    atkeys_file->_initialized_fields[ATCLIENT_ATKEYS_FILE_AES_PKAM_PRIVATE_KEY_STR_INDEX] |=
        ATCLIENT_ATKEYS_FILE_AES_PKAM_PRIVATE_KEY_STR_INITIALIZED;
  } else {
    atkeys_file->_initialized_fields[ATCLIENT_ATKEYS_FILE_AES_PKAM_PRIVATE_KEY_STR_INDEX] &=
        ~ATCLIENT_ATKEYS_FILE_AES_PKAM_PRIVATE_KEY_STR_INITIALIZED;
  }
}

static void set_aes_encrypt_public_key_str_initialized(atclient_atkeys_file *atkeys_file, const bool initialized) {
  if (initialized) {
    atkeys_file->_initialized_fields[ATCLIENT_ATKEYS_FILE_AES_ENCRYPT_PUBLIC_KEY_STR_INDEX] |=
        ATCLIENT_ATKEYS_FILE_AES_ENCRYPT_PUBLIC_KEY_STR_INITIALIZED;
  } else {
    atkeys_file->_initialized_fields[ATCLIENT_ATKEYS_FILE_AES_ENCRYPT_PUBLIC_KEY_STR_INDEX] &=
        ~ATCLIENT_ATKEYS_FILE_AES_ENCRYPT_PUBLIC_KEY_STR_INITIALIZED;
  }
}

static void set_aes_encrypt_private_key_str_initialized(atclient_atkeys_file *atkeys_file, const bool initialized) {
  if (initialized) {
    atkeys_file->_initialized_fields[ATCLIENT_ATKEYS_FILE_AES_ENCRYPT_PRIVATE_KEY_STR_INDEX] |=
        ATCLIENT_ATKEYS_FILE_AES_ENCRYPT_PRIVATE_KEY_STR_INITIALIZED;
  } else {
    atkeys_file->_initialized_fields[ATCLIENT_ATKEYS_FILE_AES_ENCRYPT_PRIVATE_KEY_STR_INDEX] &=
        ~ATCLIENT_ATKEYS_FILE_AES_ENCRYPT_PRIVATE_KEY_STR_INITIALIZED;
  }
}

static void set_self_encryption_key_str_initialized(atclient_atkeys_file *atkeys_file, const bool initialized) {
  if (initialized) {
    atkeys_file->_initialized_fields[ATCLIENT_ATKEYS_FILE_SELF_ENCRYPTION_KEY_STR_INDEX] |=
        ATCLIENT_ATKEYS_FILE_SELF_ENCRYPTION_KEY_STR_INITIALIZED;
  } else {
    atkeys_file->_initialized_fields[ATCLIENT_ATKEYS_FILE_SELF_ENCRYPTION_KEY_STR_INDEX] &=
        ~ATCLIENT_ATKEYS_FILE_SELF_ENCRYPTION_KEY_STR_INITIALIZED;
  }
}

static void unset_aes_pkam_public_key_str(atclient_atkeys_file *atkeys_file) {
  if (is_aes_pkam_public_key_str_initialized(atkeys_file)) {
    free(atkeys_file->aes_pkam_public_key_str);
  }
  atkeys_file->aes_pkam_public_key_str = NULL;
  set_aes_pkam_public_key_str_initialized(atkeys_file, false);
}

static void unset_aes_pkam_private_key_str(atclient_atkeys_file *atkeys_file) {
  if (is_aes_pkam_private_key_str_initialized(atkeys_file)) {
    free(atkeys_file->aes_pkam_private_key_str);
  }
  atkeys_file->aes_pkam_private_key_str = NULL;
  set_aes_pkam_private_key_str_initialized(atkeys_file, false);
}

static void unset_aes_encrypt_public_key_str(atclient_atkeys_file *atkeys_file) {
  if (is_aes_encrypt_public_key_str_initialized(atkeys_file)) {
    free(atkeys_file->aes_encrypt_public_key_str);
  }
  atkeys_file->aes_encrypt_public_key_str = NULL;
  set_aes_encrypt_public_key_str_initialized(atkeys_file, false);
}

static void unset_aes_encrypt_private_key_str(atclient_atkeys_file *atkeys_file) {
  if (is_aes_encrypt_private_key_str_initialized(atkeys_file)) {
    free(atkeys_file->aes_encrypt_private_key_str);
  }
  atkeys_file->aes_encrypt_private_key_str = NULL;
  set_aes_encrypt_private_key_str_initialized(atkeys_file, false);
}

static void unset_self_encryption_key_str(atclient_atkeys_file *atkeys_file) {
  if (is_self_encryption_key_str_initialized(atkeys_file)) {
    free(atkeys_file->self_encryption_key_str);
  }
  atkeys_file->self_encryption_key_str = NULL;
  set_self_encryption_key_str_initialized(atkeys_file, false);
}

static int set_aes_pkam_public_key_str(atclient_atkeys_file *atkeys_file, const char *aes_pkam_public_key_str,
                                       const size_t aes_pkam_publickey_str_len) {
  int ret = 1;

  if (is_aes_pkam_public_key_str_initialized(atkeys_file)) {
    unset_aes_pkam_public_key_str(atkeys_file);
  }

  const size_t aes_pkam_public_key_str_size = aes_pkam_publickey_str_len + 1;
  if ((atkeys_file->aes_pkam_public_key_str = (char *)malloc(sizeof(char) * aes_pkam_public_key_str_size)) == NULL) {
    ret = 1;
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "malloc failed\n");
    goto exit;
  }

  set_aes_pkam_public_key_str_initialized(atkeys_file, true);
  memcpy(atkeys_file->aes_pkam_public_key_str, aes_pkam_public_key_str, aes_pkam_publickey_str_len);
  atkeys_file->aes_pkam_public_key_str[aes_pkam_publickey_str_len] = '\0';

  ret = 0;
  goto exit;
exit: { return ret; }
}

static int set_aes_pkam_private_key_str(atclient_atkeys_file *atkeys_file, const char *aes_pkam_private_key_str,
                                        const size_t aes_pkam_private_key_str_len) {
  int ret = 1;

  if (is_aes_pkam_private_key_str_initialized(atkeys_file)) {
    unset_aes_pkam_private_key_str(atkeys_file);
  }

  const size_t aes_pkam_private_key_str_size = aes_pkam_private_key_str_len + 1;
  if ((atkeys_file->aes_pkam_private_key_str = (char *)malloc(sizeof(char) * aes_pkam_private_key_str_size)) == NULL) {
    ret = 1;
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "malloc failed\n");
    goto exit;
  }

  set_aes_pkam_private_key_str_initialized(atkeys_file, true);
  memcpy(atkeys_file->aes_pkam_private_key_str, aes_pkam_private_key_str, aes_pkam_private_key_str_len);
  atkeys_file->aes_pkam_private_key_str[aes_pkam_private_key_str_len] = '\0';

  ret = 0;
  goto exit;
exit: { return ret; }
}
static int set_aes_encrypt_public_key_str(atclient_atkeys_file *atkeys_file, const char *aes_encrypt_public_key_str,
                                          const size_t aes_encrypt_public_key_str_len) {
  int ret = 1;

  if (is_aes_encrypt_public_key_str_initialized(atkeys_file)) {
    unset_aes_encrypt_public_key_str(atkeys_file);
  }

  const size_t aes_encrypt_public_key_str_size = aes_encrypt_public_key_str_len + 1;
  if ((atkeys_file->aes_encrypt_public_key_str = (char *)malloc(sizeof(char) * aes_encrypt_public_key_str_size)) ==
      NULL) {
    ret = 1;
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "malloc failed\n");
    goto exit;
  }

  set_aes_encrypt_public_key_str_initialized(atkeys_file, true);
  memcpy(atkeys_file->aes_encrypt_public_key_str, aes_encrypt_public_key_str, aes_encrypt_public_key_str_len);
  atkeys_file->aes_encrypt_public_key_str[aes_encrypt_public_key_str_len] = '\0';

  ret = 0;
  goto exit;

exit: { return ret; }
}

static int set_aes_encrypt_private_key_str(atclient_atkeys_file *atkeys_file, const char *aes_encrypt_private_key_str,
                                           const size_t aes_encrypt_private_key_str_len) {
  int ret = 1;

  if (is_aes_encrypt_private_key_str_initialized(atkeys_file)) {
    unset_aes_encrypt_private_key_str(atkeys_file);
  }

  const size_t aes_encrypt_private_key_str_size = aes_encrypt_private_key_str_len + 1;
  if ((atkeys_file->aes_encrypt_private_key_str = (char *)malloc(sizeof(char) * aes_encrypt_private_key_str_size)) ==
      NULL) {
    ret = 1;
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "malloc failed\n");
    goto exit;
  }

  set_aes_encrypt_private_key_str_initialized(atkeys_file, true);
  memcpy(atkeys_file->aes_encrypt_private_key_str, aes_encrypt_private_key_str, aes_encrypt_private_key_str_len);
  atkeys_file->aes_encrypt_private_key_str[aes_encrypt_private_key_str_len] = '\0';

  ret = 0;
  goto exit;
exit: { return ret; }
}

static int set_self_encryption_key_str(atclient_atkeys_file *atkeys_file, const char *self_encryption_key_str,
                                       const size_t self_encryption_key_str_len) {
  int ret = 1;

  if (is_self_encryption_key_str_initialized(atkeys_file)) {
    unset_self_encryption_key_str(atkeys_file);
  }

  const size_t selfencryptionkeystrsize = self_encryption_key_str_len + 1;
  if ((atkeys_file->self_encryption_key_str = (char *)malloc(sizeof(char) * selfencryptionkeystrsize)) == NULL) {
    ret = 1;
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "malloc failed\n");
    goto exit;
  }

  set_self_encryption_key_str_initialized(atkeys_file, true);
  memcpy(atkeys_file->self_encryption_key_str, self_encryption_key_str, self_encryption_key_str_len);
  atkeys_file->self_encryption_key_str[self_encryption_key_str_len] = '\0';

  ret = 0;
  goto exit;

exit: { return ret; }
}
