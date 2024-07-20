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

static bool is_aespkampublickeystr_initialized(atclient_atkeysfile *atkeysfile);
static bool is_aespkamprivatekeystr_initialized(atclient_atkeysfile *atkeysfile);
static bool is_aesencryptpublickeystr_initialized(atclient_atkeysfile *atkeysfile);
static bool is_aesencryptprivatekeystr_initialized(atclient_atkeysfile *atkeysfile);
static bool is_selfencryptionkeystr_initialized(atclient_atkeysfile *atkeysfile);

static void set_aespkampublickestr_initialized(atclient_atkeysfile *atkeysfile, const bool initialized);
static void set_aespkamprivatekeystr_initialized(atclient_atkeysfile *atkeysfile, const bool initialized);
static void set_aesencryptpublickeystr_initialized(atclient_atkeysfile *atkeysfile, const bool initialized);
static void set_aesencryptprivatekeystr_initialized(atclient_atkeysfile *atkeysfile, const bool initialized);
static void set_selfencryptionkeystr_initialized(atclient_atkeysfile *atkeysfile, const bool initialized);

static void unset_aespkampublickeystr(atclient_atkeysfile *atkeysfile);
static void unset_aespkamprivatekeystr(atclient_atkeysfile *atkeysfile);
static void unset_aesencryptpublickeystr(atclient_atkeysfile *atkeysfile);
static void unset_aesencryptprivatekeystr(atclient_atkeysfile *atkeysfile);
static void unset_selfencryptionkeystr(atclient_atkeysfile *atkeysfile);

static int set_aespkampublickeystr(atclient_atkeysfile *atkeysfile, const char *aespkampublickeystr,
                                   const size_t aespkampublickeystrlen);
static int set_aespkamprivatekeystr(atclient_atkeysfile *atkeysfile, const char *aespkamprivatekeystr,
                                    const size_t aespkamprivatekeystrlen);
static int set_aesencryptpublickeystr(atclient_atkeysfile *atkeysfile, const char *aesencryptpublickeystr,
                                      const size_t aesencryptpublickeystrlen);
static int set_aesencryptprivatekeystr(atclient_atkeysfile *atkeysfile, const char *aesencryptprivatekeystr,
                                       const size_t aesencryptprivatekeystrlen);
static int set_selfencryptionkeystr(atclient_atkeysfile *atkeysfile, const char *selfencryptionkeystr,
                                    const size_t selfencryptionkeystrlen);

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

  const size_t bytesread = fread(readbuf, 1, FILE_READ_BUFFER_SIZE, file);
  fclose(file);
  if (bytesread == 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "fread failed\n");
    ret = 1;
    goto exit;
  }

  root = cJSON_Parse(readbuf);
  cJSON *aespkampublickey = cJSON_GetObjectItem(root, "aesPkamPublicKey");
  cJSON *aespkamprivatekey = cJSON_GetObjectItem(root, "aesPkamPrivateKey");
  cJSON *aesencryptpublickey = cJSON_GetObjectItem(root, "aesEncryptPublicKey");
  cJSON *aesencryptprivatekey = cJSON_GetObjectItem(root, "aesEncryptPrivateKey");
  cJSON *selfencryptionkey = cJSON_GetObjectItem(root, "selfEncryptionKey");

  if (aespkamprivatekey == NULL) {
    ret = 1;
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "Error reading aesPkamPrivateKey!\n");
    goto exit;
  }

  if (aespkampublickey == NULL) {
    ret = 1;
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "Error reading aesPkamPublicKey!\n");
    goto exit;
  }

  if (aesencryptprivatekey == NULL) {
    ret = 1;
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "Error reading aesEncryptPrivateKey!\n");
    goto exit;
  }

  if (aesencryptpublickey == NULL) {
    ret = 1;
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "Error reading aesEncryptPublicKey!\n");
    goto exit;
  }

  if (selfencryptionkey == NULL) {
    ret = 1;
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "Error reading selfEncryptionKey!\n");
    goto exit;
  }

  if ((ret = set_aespkampublickeystr(atkeysfile, aespkampublickey->valuestring,
                                     strlen(aespkampublickey->valuestring))) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "set_aespkampublickeystr: %d | failed to set aespkampublickeystr\n",
                 ret);
    goto exit;
  }

  if ((ret = set_aespkamprivatekeystr(atkeysfile, aespkamprivatekey->valuestring,
                                      strlen(aespkamprivatekey->valuestring))) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR,
                 "set_aespkamprivatekeystr: %d | failed to set aespkamprivatekeystr\n", ret);
    goto exit;
  }

  if ((ret = set_aesencryptpublickeystr(atkeysfile, aesencryptpublickey->valuestring,
                                        strlen(aesencryptpublickey->valuestring))) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR,
                 "set_aesencryptpublickeystr: %d | failed to set aesencryptpublickeystr\n", ret);
    goto exit;
  }

  if ((ret = set_aesencryptprivatekeystr(atkeysfile, aesencryptprivatekey->valuestring,
                                         strlen(aesencryptprivatekey->valuestring))) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR,
                 "set_aesencryptprivatekeystr: %d | failed to set aesencryptprivatekeystr\n", ret);
    goto exit;
  }

  if ((ret = set_selfencryptionkeystr(atkeysfile, selfencryptionkey->valuestring,
                                      strlen(selfencryptionkey->valuestring))) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR,
                 "set_selfencryptionkeystr: %d | failed to set selfencryptionkeystr\n", ret);
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
  unset_aespkampublickeystr(atkeysfile);
  unset_aespkamprivatekeystr(atkeysfile);
  unset_aesencryptpublickeystr(atkeysfile);
  unset_aesencryptprivatekeystr(atkeysfile);
  unset_selfencryptionkeystr(atkeysfile);
}

static bool is_aespkampublickeystr_initialized(atclient_atkeysfile *atkeysfile) {
  return atkeysfile->_initializedfields[AESPKAMPUBLICKEYSTR_INDEX] & AESPKAMPUBLICKEYSTR_INTIIALIZED;
}

static bool is_aespkamprivatekeystr_initialized(atclient_atkeysfile *atkeysfile) {
  return atkeysfile->_initializedfields[AESPKAMPRIVATEKEYSTR_INDEX] & AESPKAMPRIVATEKEYSTR_INTIIALIZED;
}

static bool is_aesencryptpublickeystr_initialized(atclient_atkeysfile *atkeysfile) {
  return atkeysfile->_initializedfields[AESENCRYPTPUBLICKEYSTR_INDEX] & AESENCRYPTPUBLICKEYSTR_INTIIALIZED;
}

static bool is_aesencryptprivatekeystr_initialized(atclient_atkeysfile *atkeysfile) {
  return atkeysfile->_initializedfields[AESENCRYPTPRIVATEKEYSTR_INDEX] & AESENCRYPTPRIVATEKEYSTR_INTIIALIZED;
}

static bool is_selfencryptionkeystr_initialized(atclient_atkeysfile *atkeysfile) {
  return atkeysfile->_initializedfields[SELFENCRYPTIONKEYSTR_INDEX] & SELFENCRYPTIONKEYSTR_INTIIALIZED;
}

static void set_aespkampublickestr_initialized(atclient_atkeysfile *atkeysfile, const bool initialized) {
  if (initialized) {
    atkeysfile->_initializedfields[AESPKAMPUBLICKEYSTR_INDEX] |= AESPKAMPUBLICKEYSTR_INTIIALIZED;
  } else {
    atkeysfile->_initializedfields[AESPKAMPUBLICKEYSTR_INDEX] &= ~AESPKAMPUBLICKEYSTR_INTIIALIZED;
  }
}

static void set_aespkamprivatekeystr_initialized(atclient_atkeysfile *atkeysfile, const bool initialized) {
  if (initialized) {
    atkeysfile->_initializedfields[AESPKAMPRIVATEKEYSTR_INDEX] |= AESPKAMPRIVATEKEYSTR_INTIIALIZED;
  } else {
    atkeysfile->_initializedfields[AESPKAMPRIVATEKEYSTR_INDEX] &= ~AESPKAMPRIVATEKEYSTR_INTIIALIZED;
  }
}

static void set_aesencryptpublickeystr_initialized(atclient_atkeysfile *atkeysfile, const bool initialized) {
  if (initialized) {
    atkeysfile->_initializedfields[AESENCRYPTPUBLICKEYSTR_INDEX] |= AESENCRYPTPUBLICKEYSTR_INTIIALIZED;
  } else {
    atkeysfile->_initializedfields[AESENCRYPTPUBLICKEYSTR_INDEX] &= ~AESENCRYPTPUBLICKEYSTR_INTIIALIZED;
  }
}

static void set_aesencryptprivatekeystr_initialized(atclient_atkeysfile *atkeysfile, const bool initialized) {
  if (initialized) {
    atkeysfile->_initializedfields[AESENCRYPTPRIVATEKEYSTR_INDEX] |= AESENCRYPTPRIVATEKEYSTR_INTIIALIZED;
  } else {
    atkeysfile->_initializedfields[AESENCRYPTPRIVATEKEYSTR_INDEX] &= ~AESENCRYPTPRIVATEKEYSTR_INTIIALIZED;
  }
}

static void set_selfencryptionkeystr_initialized(atclient_atkeysfile *atkeysfile, const bool initialized) {
  if (initialized) {
    atkeysfile->_initializedfields[SELFENCRYPTIONKEYSTR_INDEX] |= SELFENCRYPTIONKEYSTR_INTIIALIZED;
  } else {
    atkeysfile->_initializedfields[SELFENCRYPTIONKEYSTR_INDEX] &= ~SELFENCRYPTIONKEYSTR_INTIIALIZED;
  }
}

static void unset_aespkampublickeystr(atclient_atkeysfile *atkeysfile) {
  if (is_aespkampublickeystr_initialized(atkeysfile)) {
    free(atkeysfile->aespkampublickeystr);
  }
  atkeysfile->aespkampublickeystr = NULL;
  set_aespkampublickestr_initialized(atkeysfile, false);
}

static void unset_aespkamprivatekeystr(atclient_atkeysfile *atkeysfile) {
  if (is_aespkamprivatekeystr_initialized(atkeysfile)) {
    free(atkeysfile->aespkamprivatekeystr);
  }
  atkeysfile->aespkamprivatekeystr = NULL;
  set_aespkamprivatekeystr_initialized(atkeysfile, false);
}

static void unset_aesencryptpublickeystr(atclient_atkeysfile *atkeysfile) {
  if (is_aesencryptpublickeystr_initialized(atkeysfile)) {
    free(atkeysfile->aesencryptpublickeystr);
  }
  atkeysfile->aesencryptpublickeystr = NULL;
  set_aesencryptpublickeystr_initialized(atkeysfile, false);
}

static void unset_aesencryptprivatekeystr(atclient_atkeysfile *atkeysfile) {
  if (is_aesencryptprivatekeystr_initialized(atkeysfile)) {
    free(atkeysfile->aesencryptprivatekeystr);
  }
  atkeysfile->aesencryptprivatekeystr = NULL;
  set_aesencryptprivatekeystr_initialized(atkeysfile, false);
}

static void unset_selfencryptionkeystr(atclient_atkeysfile *atkeysfile) {
  if (is_selfencryptionkeystr_initialized(atkeysfile)) {
    free(atkeysfile->selfencryptionkeystr);
  }
  atkeysfile->selfencryptionkeystr = NULL;
  set_selfencryptionkeystr_initialized(atkeysfile, false);
}

static int set_aespkampublickeystr(atclient_atkeysfile *atkeysfile, const char *aespkampublickeystr,
                                   const size_t aespkampublickeystrlen) {
  int ret = 1;

  if (is_aespkampublickeystr_initialized(atkeysfile)) {
    unset_aespkampublickeystr(atkeysfile);
  }

  const size_t aespkampublickeystrsize = aespkampublickeystrlen + 1;
  if ((atkeysfile->aespkampublickeystr = (char *)malloc(sizeof(char) * aespkampublickeystrsize)) == NULL) {
    ret = 1;
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "malloc failed\n");
    goto exit;
  }

  set_aespkampublickestr_initialized(atkeysfile, true);
  memcpy(atkeysfile->aespkampublickeystr, aespkampublickeystr, aespkampublickeystrlen);
  atkeysfile->aespkampublickeystr[aespkampublickeystrlen] = '\0';

  ret = 0;
  goto exit;
exit: { return ret; }
}

static int set_aespkamprivatekeystr(atclient_atkeysfile *atkeysfile, const char *aespkamprivatekeystr,
                                    const size_t aespkamprivatekeystrlen) {
  int ret = 1;

  if (is_aespkamprivatekeystr_initialized(atkeysfile)) {
    unset_aespkamprivatekeystr(atkeysfile);
  }

  const size_t aespkamprivatekeystrsize = aespkamprivatekeystrlen + 1;
  if ((atkeysfile->aespkamprivatekeystr = (char *)malloc(sizeof(char) * aespkamprivatekeystrsize)) == NULL) {
    ret = 1;
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "malloc failed\n");
    goto exit;
  }

  set_aespkamprivatekeystr_initialized(atkeysfile, true);
  memcpy(atkeysfile->aespkamprivatekeystr, aespkamprivatekeystr, aespkamprivatekeystrlen);
  atkeysfile->aespkamprivatekeystr[aespkamprivatekeystrlen] = '\0';

  ret = 0;
  goto exit;
exit: { return ret; }
}
static int set_aesencryptpublickeystr(atclient_atkeysfile *atkeysfile, const char *aesencryptpublickeystr,
                                      const size_t aesencryptpublickeystrlen) {
  int ret = 1;

  if (is_aesencryptpublickeystr_initialized(atkeysfile)) {
    unset_aesencryptpublickeystr(atkeysfile);
  }

  const size_t aesencryptpublickeystrsize = aesencryptpublickeystrlen + 1;
  if ((atkeysfile->aesencryptpublickeystr = (char *)malloc(sizeof(char) * aesencryptpublickeystrsize)) == NULL) {
    ret = 1;
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "malloc failed\n");
    goto exit;
  }

  set_aesencryptpublickeystr_initialized(atkeysfile, true);
  memcpy(atkeysfile->aesencryptpublickeystr, aesencryptpublickeystr, aesencryptpublickeystrlen);
  atkeysfile->aesencryptpublickeystr[aesencryptpublickeystrlen] = '\0';

  ret = 0;
  goto exit;

exit: { return ret; }
}

static int set_aesencryptprivatekeystr(atclient_atkeysfile *atkeysfile, const char *aesencryptprivatekeystr,
                                       const size_t aesencryptprivatekeystrlen) {
  int ret = 1;

  if (is_aesencryptprivatekeystr_initialized(atkeysfile)) {
    unset_aesencryptprivatekeystr(atkeysfile);
  }

  const size_t aesencryptprivatekeystrsize = aesencryptprivatekeystrlen + 1;
  if ((atkeysfile->aesencryptprivatekeystr = (char *)malloc(sizeof(char) * aesencryptprivatekeystrsize)) == NULL) {
    ret = 1;
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "malloc failed\n");
    goto exit;
  }

  set_aesencryptprivatekeystr_initialized(atkeysfile, true);
  memcpy(atkeysfile->aesencryptprivatekeystr, aesencryptprivatekeystr, aesencryptprivatekeystrlen);
  atkeysfile->aesencryptprivatekeystr[aesencryptprivatekeystrlen] = '\0';

  ret = 0;
  goto exit;
exit: { return ret; }
}

static int set_selfencryptionkeystr(atclient_atkeysfile *atkeysfile, const char *selfencryptionkeystr,
                                    const size_t selfencryptionkeystrlen) {
  int ret = 1;

  if (is_selfencryptionkeystr_initialized(atkeysfile)) {
    unset_selfencryptionkeystr(atkeysfile);
  }

  const size_t selfencryptionkeystrsize = selfencryptionkeystrlen + 1;
  if ((atkeysfile->selfencryptionkeystr = (char *)malloc(sizeof(char) * selfencryptionkeystrsize)) == NULL) {
    ret = 1;
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "malloc failed\n");
    goto exit;
  }

  set_selfencryptionkeystr_initialized(atkeysfile, true);
  memcpy(atkeysfile->selfencryptionkeystr, selfencryptionkeystr, selfencryptionkeystrlen);
  atkeysfile->selfencryptionkeystr[selfencryptionkeystrlen] = '\0';

  ret = 0;
  goto exit;

exit: { return ret; }
}