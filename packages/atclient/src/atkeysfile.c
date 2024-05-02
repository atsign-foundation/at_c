#include "atclient/atkeysfile.h"
#include "atclient/atstr.h"
#include "atlogger/atlogger.h"
#include <cJSON.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// represents the buffer size of an encrypted RSA key in base64 format
#define BASE64_ENCRYPTED_KEY_BUFFER_SIZE 4096

// represents buffer size of reading the entire atKeys file
#define FILE_READ_BUFFER_SIZE 8192

#define TAG "atkeysfile"

void atclient_atkeysfile_init(atclient_atkeysfile *atkeysfile) {
  memset(atkeysfile, 0, sizeof(atclient_atkeysfile));

  atclient_atstr_init(&(atkeysfile->aespkampublickeystr), BASE64_ENCRYPTED_KEY_BUFFER_SIZE);
  atclient_atstr_init(&(atkeysfile->aespkamprivatekeystr), BASE64_ENCRYPTED_KEY_BUFFER_SIZE);
  atclient_atstr_init(&(atkeysfile->aesencryptpublickeystr), BASE64_ENCRYPTED_KEY_BUFFER_SIZE);
  atclient_atstr_init(&(atkeysfile->aesencryptprivatekeystr), BASE64_ENCRYPTED_KEY_BUFFER_SIZE);
  atclient_atstr_init(&(atkeysfile->selfencryptionkeystr), BASE64_ENCRYPTED_KEY_BUFFER_SIZE);
}

int atclient_atkeysfile_read(atclient_atkeysfile *atkeysfile, const char *path) {
  int ret = 1;
  cJSON *root = NULL;

  FILE *file = fopen(path, "r");

  atclient_atstr readbuf;
  atclient_atstr_init(&readbuf, FILE_READ_BUFFER_SIZE);

  if (file == NULL) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "fopen failed\n");
    ret = 1;
    goto exit;
  }

  const size_t bytesread = fread(readbuf.str, 1, FILE_READ_BUFFER_SIZE, file);
  if (bytesread == 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "fread failed\n");
    ret = 1;
    goto exit;
  }

  root = cJSON_Parse(readbuf.str);
  cJSON *aespkampublickey = cJSON_GetObjectItem(root, "aesPkamPublicKey");
  cJSON *aespkamprivatekey = cJSON_GetObjectItem(root, "aesPkamPrivateKey");
  cJSON *aesencryptpublickey = cJSON_GetObjectItem(root, "aesEncryptPublicKey");
  cJSON *aesencryptprivatekey = cJSON_GetObjectItem(root, "aesEncryptPrivateKey");
  cJSON *selfencryptionkey = cJSON_GetObjectItem(root, "selfEncryptionKey");

  if (aespkamprivatekey == NULL) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "Error reading aesPkamPrivateKey!\n");
    ret = 1;
    goto exit;
  }

  if (aespkampublickey == NULL) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "Error reading aesPkamPublicKey!\n");
    ret = 1;
    goto exit;
  }

  if (aesencryptprivatekey == NULL) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "Error reading aesEncryptPrivateKey!\n");
    ret = 1;
    goto exit;
  }

  if (aesencryptpublickey == NULL) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "Error reading aesEncryptPublicKey!\n");
    ret = 1;
    goto exit;
  }

  if (selfencryptionkey == NULL) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "Error reading selfEncryptionKey!\n");
    ret = 1;
    goto exit;
  }

  ret = atclient_atstr_set(&(atkeysfile->aespkampublickeystr), aespkampublickey->valuestring,
                           strlen(aespkampublickey->valuestring));
  if (ret != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR,
                          "atclient_atstr_set: %d | failed to set aespkampublickeystr\n", ret);
    goto exit;
  }

  ret = atclient_atstr_set(&(atkeysfile->aespkamprivatekeystr), aespkamprivatekey->valuestring,
                           strlen(aespkamprivatekey->valuestring));
  if (ret != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR,
                          "atclient_atstr_set: %d | failed to set aespkamprivatekeystr\n", ret);
    goto exit;
  }

  ret = atclient_atstr_set(&(atkeysfile->aesencryptprivatekeystr), aesencryptprivatekey->valuestring,
                           strlen(aesencryptprivatekey->valuestring));
  if (ret != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR,
                          "atclient_atstr_set: %d | failed to set aesencryptprivatekeystr\n", ret);
    goto exit;
  }

  ret = atclient_atstr_set(&(atkeysfile->aesencryptpublickeystr), aesencryptpublickey->valuestring,
                           strlen(aesencryptpublickey->valuestring));
  if (ret != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR,
                          "atclient_atstr_set: %d | failed to set aesencryptpublickeystr\n", ret);
    goto exit;
  }

  ret = atclient_atstr_set(&(atkeysfile->selfencryptionkeystr), selfencryptionkey->valuestring,
                           strlen(selfencryptionkey->valuestring));
  if (ret != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR,
                          "atclient_atstr_set: %d | failed to set selfencryptionkeystr\n", ret);
    goto exit;
  }

  goto exit;

exit: {
  if (root != NULL) {
    cJSON_Delete(root);
  }
  fclose(file);
  atclient_atstr_free(&readbuf);
  return ret;
}
}

int atclient_atkeysfile_write(const atclient_atkeysfile *atkeysfile, const char *path, const char *atsign) {
  int ret = 1;

  // guarantee that all values are null terminated and are of correct length
  atclient_atstr aespkampublickey;
  atclient_atstr_init(&aespkampublickey, atkeysfile->aespkampublickeystr.len + 1);

  atclient_atstr aespkamprivatekey;
  atclient_atstr_init(&aespkamprivatekey, atkeysfile->aespkamprivatekeystr.len + 1);

  atclient_atstr aesencryptprivatekey;
  atclient_atstr_init(&aesencryptprivatekey, atkeysfile->aesencryptprivatekeystr.len + 1);

  atclient_atstr aesencryptpublickey;
  atclient_atstr_init(&aesencryptpublickey, atkeysfile->aesencryptpublickeystr.len + 1);

  atclient_atstr selfencryptionkey;
  atclient_atstr_init(&selfencryptionkey, atkeysfile->selfencryptionkeystr.len + 1);

  // create cJSON object
  cJSON *root = cJSON_CreateObject();
  cJSON_AddStringToObject(root, "aesPkamPrivateKey", aespkamprivatekey.str);
  cJSON_AddStringToObject(root, "aesPkamPublicKey", aespkampublickey.str);
  cJSON_AddStringToObject(root, "aesEncryptPrivateKey", aesencryptprivatekey.str);
  cJSON_AddStringToObject(root, "aesEncryptPublicKey", aesencryptpublickey.str);
  cJSON_AddStringToObject(root, "selfEncryptionKey", selfencryptionkey.str);

  ret =
      atclient_atstr_set(&aespkampublickey, atkeysfile->aespkampublickeystr.str, atkeysfile->aespkampublickeystr.len);
  if (ret != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR,
                          "atclient_atstr_set: %d | failed to set aespkampublickeystr\n", ret);
    goto exit;
  }

  ret = atclient_atstr_set(&aespkamprivatekey, atkeysfile->aespkamprivatekeystr.str,
                           atkeysfile->aespkamprivatekeystr.len);
  if (ret != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR,
                          "atclient_atstr_set: %d | failed to set aespkamprivatekeystr\n", ret);
    goto exit;
  }

  ret = atclient_atstr_set(&aesencryptprivatekey, atkeysfile->aesencryptprivatekeystr.str,
                           atkeysfile->aesencryptprivatekeystr.len);
  if (ret != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR,
                          "atclient_atstr_set: %d | failed to set aesencryptprivatekeystr\n", ret);
    goto exit;
  }

  ret = atclient_atstr_set(&aesencryptpublickey, atkeysfile->aesencryptpublickeystr.str,
                           atkeysfile->aesencryptpublickeystr.len);
  if (ret != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR,
                          "atclient_atstr_set: %d | failed to set aesencryptpublickeystr\n", ret);
    goto exit;
  }

  ret = atclient_atstr_set(&selfencryptionkey, atkeysfile->selfencryptionkeystr.str,
                           atkeysfile->selfencryptionkeystr.len);
  if (ret != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR,
                          "atclient_atstr_set: %d | failed to set selfencryptionkeystr\n", ret);
    goto exit;
  }

  // check that atkeysfile has populated values
  if (atkeysfile->aespkamprivatekeystr.len == 0 || atkeysfile->aespkampublickeystr.len == 0 ||
      atkeysfile->aesencryptprivatekeystr.len == 0 || atkeysfile->aesencryptpublickeystr.len == 0 ||
      atkeysfile->selfencryptionkeystr.len == 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atkeysfile has not been populated with values\n");
    ret = 1;
    goto exit;
  }

  ret = 0;

  goto exit;

exit: {
  atclient_atstr_free(&aespkamprivatekey);
  atclient_atstr_free(&aespkampublickey);
  atclient_atstr_free(&aesencryptprivatekey);
  atclient_atstr_free(&aesencryptpublickey);
  atclient_atstr_free(&selfencryptionkey);
  cJSON_Delete(root);
  return ret;
}
}

void atclient_atkeysfile_free(atclient_atkeysfile *atkeysfile) {
  atclient_atstr_free(&(atkeysfile->aespkamprivatekeystr));
  atclient_atstr_free(&(atkeysfile->aespkampublickeystr));
  atclient_atstr_free(&(atkeysfile->aesencryptprivatekeystr));
  atclient_atstr_free(&(atkeysfile->aesencryptpublickeystr));
  atclient_atstr_free(&(atkeysfile->selfencryptionkeystr));
}
