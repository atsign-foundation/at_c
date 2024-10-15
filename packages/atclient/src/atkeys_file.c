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
static bool is_apkam_symmetric_key_str_initialized(atclient_atkeys_file *atkeys_file);
static bool is_enrollment_id_str_initialized(atclient_atkeys_file *atkeys_file);

static void set_aes_pkam_public_key_str_initialized(atclient_atkeys_file *atkeys_file, const bool initialized);
static void set_aes_pkam_private_key_str_initialized(atclient_atkeys_file *atkeys_file, const bool initialized);
static void set_aes_encrypt_public_key_str_initialized(atclient_atkeys_file *atkeys_file, const bool initialized);
static void set_aes_encrypt_private_key_str_initialized(atclient_atkeys_file *atkeys_file, const bool initialized);
static void set_self_encryption_key_str_initialized(atclient_atkeys_file *atkeys_file, const bool initialized);
static void set_apkam_symmetric_key_str_initialized(atclient_atkeys_file *atkeys_file, const bool initialized);
static void set_enrollment_id_str_initialized(atclient_atkeys_file *atkeys_file, const bool initialized);

static void unset_aes_pkam_public_key_str(atclient_atkeys_file *atkeys_file);
static void unset_aes_pkam_private_key_str(atclient_atkeys_file *atkeys_file);
static void unset_aes_encrypt_public_key_str(atclient_atkeys_file *atkeys_file);
static void unset_aes_encrypt_private_key_str(atclient_atkeys_file *atkeys_file);
static void unset_self_encryption_key_str(atclient_atkeys_file *atkeys_file);
static void unset_apkam_symmetric_key_str(atclient_atkeys_file *atkeys_file);
static void unset_enrollment_id_str(atclient_atkeys_file *atkeys_file);

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
static int set_apkam_symmetric_key_str(atclient_atkeys_file *atkeys_file, const char *apkam_symmetric_key_str,
                                       const size_t apkam_symmetric_key_str_len);
static int set_enrollment_id_str(atclient_atkeys_file *atkeys_file, const char *enrollment_id_str,
                                 const size_t enrollment_id_str_len);

void atclient_atkeys_file_init(atclient_atkeys_file *atkeys_file) {
  memset(atkeys_file, 0, sizeof(atclient_atkeys_file));
}

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

  cJSON *aes_pkam_public_key = cJSON_GetObjectItem(root, ATCLIENT_ATKEYS_FILE_APKAM_PUBLIC_KEY_JSON_KEY);
  if (aes_pkam_public_key == NULL) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "Failed to read aesPkamPublicKey from JSON\n");
    goto exit;
  }

  if ((ret = set_aes_pkam_public_key_str(atkeys_file, aes_pkam_public_key->valuestring,
                                         strlen(aes_pkam_public_key->valuestring))) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "set_aes_pkam_public_key_str: %d\n", ret);
    goto exit;
  }

  cJSON *aes_pkam_private_key = cJSON_GetObjectItem(root, ATCLIENT_ATKEYS_FILE_APKAM_PRIVATE_KEY_JSON_KEY);
  if (aes_pkam_private_key == NULL) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "Failed to read aesPkamPrivateKey from JSON\n");
    goto exit;
  }
  if ((ret = set_aes_pkam_private_key_str(atkeys_file, aes_pkam_private_key->valuestring,
                                          strlen(aes_pkam_private_key->valuestring))) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "set_aes_pkam_private_key_str: %d\n", ret);
    goto exit;
  }

  cJSON *aes_encrypt_public_key =
      cJSON_GetObjectItem(root, ATCLIENT_ATKEYS_FILE_DEFAULT_ENCRYPTION_PUBLIC_KEY_JSON_KEY);
  if (aes_encrypt_public_key == NULL) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "Failed to read aesEncryptPublicKey from JSON\n");
    goto exit;
  }
  if ((ret = set_aes_encrypt_public_key_str(atkeys_file, aes_encrypt_public_key->valuestring,
                                            strlen(aes_encrypt_public_key->valuestring))) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "set_aes_encrypt_public_key_str: %d\n", ret);
    goto exit;
  }

  cJSON *aes_encrypt_private_key =
      cJSON_GetObjectItem(root, ATCLIENT_ATKEYS_FILE_DEFAULT_ENCRYPTION_PRIVATE_KEY_JSON_KEY);
  if (aes_encrypt_private_key == NULL) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "Failed to read aesEncryptPrivateKey from JSON\n");
    goto exit;
  }
  if ((ret = set_aes_encrypt_private_key_str(atkeys_file, aes_encrypt_private_key->valuestring,
                                             strlen(aes_encrypt_private_key->valuestring))) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "set_aes_encrypt_private_key_str: %d\n", ret);
    goto exit;
  }

  cJSON *self_encryption_key = cJSON_GetObjectItem(root, ATCLIENT_ATKEYS_FILE_DEFAULT_SELF_ENCRYPTION_KEY_JSON_KEY);
  if (self_encryption_key == NULL) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "Failed to read selfEncryptionKey from JSON\n");
    goto exit;
  }
  if ((ret = set_self_encryption_key_str(atkeys_file, self_encryption_key->valuestring,
                                         strlen(self_encryption_key->valuestring))) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "set_self_encryption_key_str: %d\n", ret);
    goto exit;
  }

  cJSON *apkam_symmetric_key = cJSON_GetObjectItem(root, ATCLIENT_ATKEYS_FILE_APKAM_SYMMETRIC_KEY_JSON_KEY);
  if (apkam_symmetric_key == NULL) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "Failed to read apkamSymmetricKey from JSON\n");
    goto exit;
  }
  if ((ret = set_apkam_symmetric_key_str(atkeys_file, apkam_symmetric_key->valuestring,
                                         strlen(apkam_symmetric_key->valuestring))) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "set_apkam_symmetric_key_str: %d\n", ret);
    goto exit;
  }

  cJSON *enrollment_id = cJSON_GetObjectItem(root, ATCLIENT_ATKEYS_FILE_APKAM_ENROLLMENT_ID_JSON_KEY);
  if (enrollment_id != NULL) {
    if ((ret = set_enrollment_id_str(atkeys_file, enrollment_id->valuestring, strlen(enrollment_id->valuestring))) !=
        0) {
      atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "set_enrollment_id_str: %d\n", ret);
      goto exit;
    }
  }

  ret = 0;

exit: {
  cJSON_Delete(root);
  return ret;
}
}

int atclient_atkeys_file_write_to_path(atclient_atkeys_file *atkeys_file, const char *path) {
  int ret = 1;

  /*
   * 1. Validate arguments
   */
  if (atkeys_file == NULL) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atkeys_file is NULL\n");
    return ret;
  }

  if (!atclient_atkeys_file_is_aes_encrypt_private_key_str_initialized(atkeys_file)) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "aes_encrypt_private_key_str is not initialized\n");
    return ret;
  }

  if (!atclient_atkeys_file_is_aes_encrypt_public_key_str_initialized(atkeys_file)) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "aes_encrypt_public_key_str is not initialized\n");
    return ret;
  }

  if (!atclient_atkeys_file_is_aes_pkam_private_key_str_initialized(atkeys_file)) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "aes_pkam_private_key_str is not initialized\n");
    return ret;
  }

  if (!atclient_atkeys_file_is_aes_pkam_public_key_str_initialized(atkeys_file)) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "aes_pkam_public_key_str is not initialized\n");
    return ret;
  }

  if (!atclient_atkeys_file_is_self_encryption_key_str_initialized(atkeys_file)) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "self_encryption_key_str is not initialized\n");
    return ret;
  }

  if (path == NULL) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "path is NULL\n");
    return ret;
  }

  /*
   * 2. Variables
   */

  cJSON *root = NULL; // free later
  char *json_str = NULL; // free later

  root = cJSON_CreateObject();
  if (root == NULL) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "cJSON_CreateObject failed\n");
    goto exit;
  }

  if (is_aes_pkam_public_key_str_initialized(atkeys_file)) {
    cJSON_AddStringToObject(root, "aesPkamPublicKey", atkeys_file->aes_pkam_public_key_str);
  }

  if (is_aes_pkam_private_key_str_initialized(atkeys_file)) {
    cJSON_AddStringToObject(root, "aesPkamPrivateKey", atkeys_file->aes_pkam_private_key_str);
  }

  if (is_aes_encrypt_public_key_str_initialized(atkeys_file)) {
    cJSON_AddStringToObject(root, "aesEncryptPublicKey", atkeys_file->aes_encrypt_public_key_str);
  }

  if (is_aes_encrypt_private_key_str_initialized(atkeys_file)) {
    cJSON_AddStringToObject(root, "aesEncryptPrivateKey", atkeys_file->aes_encrypt_private_key_str);
  }

  if (is_self_encryption_key_str_initialized(atkeys_file)) {
    cJSON_AddStringToObject(root, "selfEncryptionKey", atkeys_file->self_encryption_key_str);
  }

  if (is_enrollment_id_str_initialized(atkeys_file)) {
    cJSON_AddStringToObject(root, "enrollmentId", atkeys_file->enrollment_id_str);
  }

  json_str = cJSON_PrintUnformatted(root);
  if (json_str == NULL) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "cJSON_Print failed\n");
    goto exit;
  }

  FILE *file = fopen(path, "w");
  if (file == NULL) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "fopen failed\n");
    goto exit;
  }

  const size_t bytes_written = fwrite(json_str, 1, strlen(json_str), file);
  fclose(file);
  if (bytes_written == 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "fwrite failed\n");
    goto exit;
  }

  ret = 0;
exit: {
  if(json_str != NULL) {
    free(json_str);
  }
  if(root != NULL) {
    cJSON_Delete(root);
  }
  return ret;
}
}

void atclient_atkeys_file_free(atclient_atkeys_file *atkeys_file) {
  unset_aes_pkam_public_key_str(atkeys_file);
  unset_aes_pkam_private_key_str(atkeys_file);
  unset_aes_encrypt_public_key_str(atkeys_file);
  unset_aes_encrypt_private_key_str(atkeys_file);
  unset_self_encryption_key_str(atkeys_file);
  unset_apkam_symmetric_key_str(atkeys_file);
  unset_enrollment_id_str(atkeys_file);
}

bool atclient_atkeys_file_is_pkam_public_key_str_initialized(atclient_atkeys_file *atkeys_file) {
  return is_aes_pkam_public_key_str_initialized(atkeys_file);
}

bool atclient_atkeys_file_is_pkam_private_key_str_initialized(atclient_atkeys_file *atkeys_file) {
  return is_aes_pkam_private_key_str_initialized(atkeys_file);
}

bool atclient_atkeys_file_is_aes_encrypt_public_key_str_initialized(atclient_atkeys_file *atkeys_file) {
  return is_aes_encrypt_public_key_str_initialized(atkeys_file);
}

bool atclient_atkeys_file_is_aes_encrypt_private_key_str_initialized(atclient_atkeys_file *atkeys_file) {
  return is_aes_encrypt_private_key_str_initialized(atkeys_file);
}

bool atclient_atkeys_file_is_self_encryption_key_str_initialized(atclient_atkeys_file *atkeys_file) {
  return is_self_encryption_key_str_initialized(atkeys_file);
}

bool atclient_atkeys_file_is_apkam_symmetric_key_str_initialized(atclient_atkeys_file *atkeys_file) {
  return is_enrollment_id_str_initialized(atkeys_file);
}

bool atclient_atkeys_file_is_enrollment_id_str_initialized(atclient_atkeys_file *atkeys_file) {
  return is_apkam_symmetric_key_str_initialized(atkeys_file);
}

int atclient_atkeys_file_set_aes_pkam_public_key_str(atclient_atkeys_file *atkeys_file,
                                                     const char *aes_pkam_public_key_str,
                                                     const size_t aes_pkam_public_key_str_len) {
  int ret = 1;

  if (aes_pkam_public_key_str == NULL) {
    ret = 1;
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "aes_pkam_public_key_str is NULL\n");
    return ret;
  }

  if (aes_pkam_public_key_str_len == 0) {
    ret = 1;
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "aes_pkam_public_key_str_len is 0\n");
    return ret;
  }

  if (is_aes_pkam_public_key_str_initialized(atkeys_file)) {
    unset_aes_pkam_public_key_str(atkeys_file);
  }

  if ((ret = set_aes_pkam_public_key_str(atkeys_file, aes_pkam_public_key_str, aes_pkam_public_key_str_len)) != 0) {
    ret = 1;
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "set_aes_pkam_public_key_str: %d\n", ret);
    goto exit;
  }

  ret = 0;
  goto exit;
exit: { return ret; }
}

int atclient_atkeys_file_set_aes_pkam_private_key_str(atclient_atkeys_file *atkeys_file,
                                                      const char *aes_pkam_private_key_str,
                                                      const size_t aes_pkam_private_key_str_len) {
  int ret = 1;

  if (aes_pkam_private_key_str == NULL) {
    ret = 1;
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "aes_pkam_private_key_str is NULL\n");
    return ret;
  }

  if (aes_pkam_private_key_str_len == 0) {
    ret = 1;
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "aes_pkam_private_key_str_len is 0\n");
    return ret;
  }

  if (is_aes_pkam_private_key_str_initialized(atkeys_file)) {
    unset_aes_pkam_private_key_str(atkeys_file);
  }

  if ((ret = set_aes_pkam_private_key_str(atkeys_file, aes_pkam_private_key_str, aes_pkam_private_key_str_len)) != 0) {
    ret = 1;
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "set_aes_pkam_private_key_str: %d\n", ret);
    goto exit;
  }

  ret = 0;
  goto exit;
exit: { return ret; }
}

int atclient_atkeys_file_set_aes_encrypt_public_key_str(atclient_atkeys_file *atkeys_file,
                                                        const char *aes_encrypt_public_key_str,
                                                        const size_t aes_encrypt_public_key_str_len) {
  int ret = 1;

  if (aes_encrypt_public_key_str == NULL) {
    ret = 1;
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "aes_encrypt_public_key_str is NULL\n");
    return ret;
  }

  if (aes_encrypt_public_key_str_len == 0) {
    ret = 1;
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "aes_encrypt_public_key_str_len is 0\n");
    return ret;
  }

  if (is_aes_encrypt_public_key_str_initialized(atkeys_file)) {
    unset_aes_encrypt_public_key_str(atkeys_file);
  }

  if ((ret = set_aes_encrypt_public_key_str(atkeys_file, aes_encrypt_public_key_str, aes_encrypt_public_key_str_len)) !=
      0) {
    ret = 1;
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "set_aes_encrypt_public_key_str: %d\n", ret);
    goto exit;
  }

  ret = 0;
  goto exit;
exit: { return ret; }
}

int atclient_atkeys_file_set_aes_encrypt_private_key_str(atclient_atkeys_file *atkeys_file,
                                                         const char *aes_encrypt_private_key_str,
                                                         const size_t aes_encrypt_private_key_str_len) {
  int ret = 1;

  if (aes_encrypt_private_key_str == NULL) {
    ret = 1;
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "aes_encrypt_private_key_str is NULL\n");
    return ret;
  }

  if (aes_encrypt_private_key_str_len == 0) {
    ret = 1;
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "aes_encrypt_private_key_str_len is 0\n");
    return ret;
  }

  if (is_aes_encrypt_private_key_str_initialized(atkeys_file)) {
    unset_aes_encrypt_private_key_str(atkeys_file);
  }

  if ((ret = set_aes_encrypt_private_key_str(atkeys_file, aes_encrypt_private_key_str,
                                             aes_encrypt_private_key_str_len)) != 0) {
    ret = 1;
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "set_aes_encrypt_private_key_str: %d\n", ret);
    goto exit;
  }

  ret = 0;
  goto exit;
exit: { return ret; }
}

int atclient_atkeys_file_set_self_encryption_key_str(atclient_atkeys_file *atkeys_file,
                                                     const char *self_encryption_key_str,
                                                     const size_t self_encryption_key_str_len) {
  int ret = 1;

  if (self_encryption_key_str == NULL) {
    ret = 1;
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "self_encryption_key_str is NULL\n");
    return ret;
  }

  if (self_encryption_key_str_len == 0) {
    ret = 1;
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "self_encryption_key_str_len is 0\n");
    return ret;
  }

  if (is_self_encryption_key_str_initialized(atkeys_file)) {
    unset_self_encryption_key_str(atkeys_file);
  }

  if ((ret = set_self_encryption_key_str(atkeys_file, self_encryption_key_str, self_encryption_key_str_len)) != 0) {
    ret = 1;
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "set_self_encryption_key_str: %d\n", ret);
    goto exit;
  }

  ret = 0;
  goto exit;
exit: { return ret; }
}

int atclient_atkeys_file_set_apkam_symmetric_key_str(atclient_atkeys_file *atkeys_file,
                                                     const char *apkam_symmetric_key_str,
                                                     const size_t apkam_symmetric_key_str_len) {
  int ret = 1;

  if (apkam_symmetric_key_str == NULL) {
    ret = 1;
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "apkam_symmetric_key_str is NULL\n");
    return ret;
  }

  if (apkam_symmetric_key_str_len == 0) {
    ret = 1;
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "apkam_symmetric_key_str_len is 0\n");
    return ret;
  }

  if (is_apkam_symmetric_key_str_initialized(atkeys_file)) {
    unset_apkam_symmetric_key_str(atkeys_file);
  }

  if ((ret = set_apkam_symmetric_key_str(atkeys_file, apkam_symmetric_key_str, apkam_symmetric_key_str_len)) != 0) {
    ret = 1;
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "set_apkam_symmetric_key_str: %d\n", ret);
    goto exit;
  }

  ret = 0;
  goto exit;
exit: { return ret; }
}

int atclient_atkeys_file_set_enrollment_id_str(atclient_atkeys_file *atkeys_file, const char *enrollment_id_str,
                                               const size_t enrollment_id_str_len) {
  int ret = 1;

  if (enrollment_id_str == NULL) {
    ret = 1;
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "enrollment_id_str is NULL\n");
    return ret;
  }

  if (enrollment_id_str_len == 0) {
    ret = 1;
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "enrollment_id_str_len is 0\n");
    return ret;
  }

  if (is_enrollment_id_str_initialized(atkeys_file)) {
    unset_enrollment_id_str(atkeys_file);
  }

  if ((ret = set_enrollment_id_str(atkeys_file, enrollment_id_str, enrollment_id_str_len)) != 0) {
    ret = 1;
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "set_enrollment_id_str: %d\n", ret);
    goto exit;
  }

  ret = 0;
  goto exit;
exit: { return ret; }
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

static bool is_apkam_symmetric_key_str_initialized(atclient_atkeys_file *atkeys_file) {
  return atkeys_file->_initialized_fields[ATCLIENT_ATKEYS_FILE_APKAM_SYMMETRIC_KEY_STR_INDEX] &
         ATCLIENT_ATKEYS_FILE_APKAM_SYMMETRIC_KEY_STR_INITIALIZED;
}

static bool is_enrollment_id_str_initialized(atclient_atkeys_file *atkeys_file) {
  return atkeys_file->_initialized_fields[ATCLIENT_ATKEYS_FILE_ENROLLMENT_ID_STR_INDEX] &
         ATCLIENT_ATKEYS_FILE_ENROLLMENT_ID_STR_INITIALIZED;
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

static void set_apkam_symmetric_key_str_initialized(atclient_atkeys_file *atkeys_file, const bool initialized) {
  if (initialized) {
    atkeys_file->_initialized_fields[ATCLIENT_ATKEYS_FILE_APKAM_SYMMETRIC_KEY_STR_INDEX] |=
        ATCLIENT_ATKEYS_FILE_APKAM_SYMMETRIC_KEY_STR_INITIALIZED;
  } else {
    atkeys_file->_initialized_fields[ATCLIENT_ATKEYS_FILE_APKAM_SYMMETRIC_KEY_STR_INDEX] &=
        ~ATCLIENT_ATKEYS_FILE_APKAM_SYMMETRIC_KEY_STR_INITIALIZED;
  }
}

static void set_enrollment_id_str_initialized(atclient_atkeys_file *atkeys_file, const bool initialized) {
  if (initialized) {
    atkeys_file->_initialized_fields[ATCLIENT_ATKEYS_FILE_ENROLLMENT_ID_STR_INDEX] |=
        ATCLIENT_ATKEYS_FILE_ENROLLMENT_ID_STR_INITIALIZED;
  } else {
    atkeys_file->_initialized_fields[ATCLIENT_ATKEYS_FILE_ENROLLMENT_ID_STR_INDEX] &=
        ~ATCLIENT_ATKEYS_FILE_ENROLLMENT_ID_STR_INITIALIZED;
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

static void unset_apkam_symmetric_key_str(atclient_atkeys_file *atkeys_file) {
  if (is_apkam_symmetric_key_str_initialized(atkeys_file)) {
    free(atkeys_file->apkam_symmetric_key_str);
  }
  atkeys_file->apkam_symmetric_key_str = NULL;
  set_apkam_symmetric_key_str_initialized(atkeys_file, false);
}

static void unset_enrollment_id_str(atclient_atkeys_file *atkeys_file) {
  if (is_enrollment_id_str_initialized(atkeys_file)) {
    free(atkeys_file->enrollment_id_str);
  }
  atkeys_file->enrollment_id_str = NULL;
  set_enrollment_id_str_initialized(atkeys_file, false);
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

static int set_apkam_symmetric_key_str(atclient_atkeys_file *atkeys_file, const char *apkam_symmetric_key_str,
                                       const size_t apkam_symmetric_key_str_len) {
  int ret = 1;

  if (is_apkam_symmetric_key_str_initialized(atkeys_file)) {
    unset_apkam_symmetric_key_str(atkeys_file);
  }

  const size_t apkamsymmterickeystrsize = apkam_symmetric_key_str_len + 1;
  if ((atkeys_file->apkam_symmetric_key_str = (char *)malloc(sizeof(char) * apkamsymmterickeystrsize)) == NULL) {
    ret = 1;
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "malloc failed\n");
    goto exit;
  }

  set_apkam_symmetric_key_str_initialized(atkeys_file, true);
  memcpy(atkeys_file->apkam_symmetric_key_str, apkam_symmetric_key_str, apkam_symmetric_key_str_len);
  atkeys_file->apkam_symmetric_key_str[apkam_symmetric_key_str_len] = '\0';

  ret = 0;
  goto exit;

exit: { return ret; }
}

static int set_enrollment_id_str(atclient_atkeys_file *atkeys_file, const char *enrollment_id_str,
                                 const size_t enrollment_id_str_len) {
  int ret = 1;

  if (is_enrollment_id_str_initialized(atkeys_file)) {
    unset_enrollment_id_str(atkeys_file);
  }

  const size_t enrollment_id_str_size = enrollment_id_str_len + 1;
  if ((atkeys_file->enrollment_id_str = (char *)malloc(sizeof(char) * enrollment_id_str_size)) == NULL) {
    ret = 1;
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "malloc failed\n");
    goto exit;
  }

  set_enrollment_id_str_initialized(atkeys_file, true);
  memcpy(atkeys_file->enrollment_id_str, enrollment_id_str, enrollment_id_str_len);
  atkeys_file->enrollment_id_str[enrollment_id_str_len] = '\0';

  ret = 0;
  goto exit;
exit: { return ret; }
}
