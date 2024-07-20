#include "atclient/metadata.h"
#include "atclient/stringutils.h"
#include "atlogger/atlogger.h"
#include "cJSON.h"
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define TAG "metadata"

static bool is_createdby_initialized(const atclient_atkey_metadata *metadata);
static bool is_updatedby_initialized(const atclient_atkey_metadata *metadata);
static bool is_status_initialized(const atclient_atkey_metadata *metadata);
static bool is_version_initialized(const atclient_atkey_metadata *metadata);
static bool is_expiresat_initialized(const atclient_atkey_metadata *metadata);
static bool is_availableat_initialized(const atclient_atkey_metadata *metadata);
static bool is_refreshat_initialized(const atclient_atkey_metadata *metadata);
static bool is_createdat_initialized(const atclient_atkey_metadata *metadata);
static bool is_updatedat_initialized(const atclient_atkey_metadata *metadata);
static bool is_ispublic_initialized(const atclient_atkey_metadata *metadata);
static bool is_iscached_initialized(const atclient_atkey_metadata *metadata);
static bool is_ttl_initialized(const atclient_atkey_metadata *metadata);
static bool is_ttb_initialized(const atclient_atkey_metadata *metadata);
static bool is_ttr_initialized(const atclient_atkey_metadata *metadata);
static bool is_ccd_initialized(const atclient_atkey_metadata *metadata);
static bool is_isbinary_initialized(const atclient_atkey_metadata *metadata);
static bool is_isencrypted_initialized(const atclient_atkey_metadata *metadata);
static bool is_datasignature_initialized(const atclient_atkey_metadata *metadata);
static bool is_sharedkeystatus_initialized(const atclient_atkey_metadata *metadata);
static bool is_sharedkeyenc_initialized(const atclient_atkey_metadata *metadata);
static bool is_pubkeyhash_initialized(const atclient_atkey_metadata *metadata);
static bool is_pubkeyalgo_initialized(const atclient_atkey_metadata *metadata);
static bool is_encoding_initialized(const atclient_atkey_metadata *metadata);
static bool is_enckeyname_initialized(const atclient_atkey_metadata *metadata);
static bool is_encalgo_initialized(const atclient_atkey_metadata *metadata);
static bool is_ivnonce_initialized(const atclient_atkey_metadata *metadata);
static bool is_skeenckeyname_initialized(const atclient_atkey_metadata *metadata);
static bool is_skeencalgo_initialized(const atclient_atkey_metadata *metadata);

static void set_is_createdby_initialized(atclient_atkey_metadata *metadata, bool is_initialized);
static void set_is_updatedby_initialized(atclient_atkey_metadata *metadata, bool is_initialized);
static void set_is_status_initialized(atclient_atkey_metadata *metadata, bool is_initialized);
static void set_is_version_initialized(atclient_atkey_metadata *metadata, bool is_initialized);
static void set_is_availableat_initialized(atclient_atkey_metadata *metadata, bool is_initialized);
static void set_is_expiresat_initialized(atclient_atkey_metadata *metadata, bool is_initialized);
static void set_is_refreshat_initialized(atclient_atkey_metadata *metadata, bool is_initialized);
static void set_is_createdat_initialized(atclient_atkey_metadata *metadata, bool is_initialized);
static void set_is_updatedat_initialized(atclient_atkey_metadata *metadata, bool is_initialized);
static void set_is_ispublic_initialized(atclient_atkey_metadata *metadata, bool is_initialized);
static void set_is_iscached_initialized(atclient_atkey_metadata *metadata, bool is_initialized);
static void set_is_ttl_initialized(atclient_atkey_metadata *metadata, bool is_initialized);
static void set_is_ttb_initialized(atclient_atkey_metadata *metadata, bool is_initialized);
static void set_is_ttr_initialized(atclient_atkey_metadata *metadata, bool is_initialized);
static void set_is_ccd_initialized(atclient_atkey_metadata *metadata, bool is_initialized);
static void set_is_isbinary_initialized(atclient_atkey_metadata *metadata, bool is_initialized);
static void set_is_isencrypted_initialized(atclient_atkey_metadata *metadata, bool is_initialized);
static void set_is_datasignature_initialized(atclient_atkey_metadata *metadata, bool is_initialized);
static void set_is_sharedkeystatus_initialized(atclient_atkey_metadata *metadata, bool is_initialized);
static void set_is_sharedkeyenc_initialized(atclient_atkey_metadata *metadata, bool is_initialized);
static void set_is_pubkeyhash_initialized(atclient_atkey_metadata *metadata, bool is_initialized);
static void set_is_pubkeyalgo_initialized(atclient_atkey_metadata *metadata, bool is_initialized);
static void set_is_encoding_initialized(atclient_atkey_metadata *metadata, bool is_initialized);
static void set_is_enckeyname_initialized(atclient_atkey_metadata *metadata, bool is_initialized);
static void set_is_encalgo_initialized(atclient_atkey_metadata *metadata, bool is_initialized);
static void set_is_ivnonce_initialized(atclient_atkey_metadata *metadata, bool is_initialized);
static void set_is_skeenckeyname_initialized(atclient_atkey_metadata *metadata, bool is_initialized);
static void set_is_skeencalgo_initialized(atclient_atkey_metadata *metadata, bool is_initialized);

static void unset_createdby(atclient_atkey_metadata *metadata);
static void unset_updatedby(atclient_atkey_metadata *metadata);
static void unset_status(atclient_atkey_metadata *metadata);
static void unset_version(atclient_atkey_metadata *metadata);
static void unset_expiresat(atclient_atkey_metadata *metadata);
static void unset_availableat(atclient_atkey_metadata *metadata);
static void unset_refreshat(atclient_atkey_metadata *metadata);
static void unset_createdat(atclient_atkey_metadata *metadata);
static void unset_updatedat(atclient_atkey_metadata *metadata);
static void unset_ispublic(atclient_atkey_metadata *metadata);
static void unset_iscached(atclient_atkey_metadata *metadata);
static void unset_ttl(atclient_atkey_metadata *metadata);
static void unset_ttb(atclient_atkey_metadata *metadata);
static void unset_ttr(atclient_atkey_metadata *metadata);
static void unset_ccd(atclient_atkey_metadata *metadata);
static void unset_isbinary(atclient_atkey_metadata *metadata);
static void unset_isencrypted(atclient_atkey_metadata *metadata);
static void unset_datasignature(atclient_atkey_metadata *metadata);
static void unset_sharedkeystatus(atclient_atkey_metadata *metadata);
static void unset_sharedkeyenc(atclient_atkey_metadata *metadata);
static void unset_pubkeyhash(atclient_atkey_metadata *metadata);
static void unset_pubkeyalgo(atclient_atkey_metadata *metadata);
static void unset_encoding(atclient_atkey_metadata *metadata);
static void unset_enckeyname(atclient_atkey_metadata *metadata);
static void unset_encalgo(atclient_atkey_metadata *metadata);
static void unset_ivnonce(atclient_atkey_metadata *metadata);
static void unset_skeenckeyname(atclient_atkey_metadata *metadata);
static void unset_skeencalgo(atclient_atkey_metadata *metadata);

static int set_createdby(atclient_atkey_metadata *metadata, const char *createdby);
static int set_updatedby(atclient_atkey_metadata *metadata, const char *updatedby);
static int set_status(atclient_atkey_metadata *metadata, const char *status);
static void set_version(atclient_atkey_metadata *metadata, int version);
static int set_expiresat(atclient_atkey_metadata *metadata, const char *expiresat);
static int set_availableat(atclient_atkey_metadata *metadata, const char *availableat);
static int set_refreshat(atclient_atkey_metadata *metadata, const char *refreshat);
static int set_createdat(atclient_atkey_metadata *metadata, const char *createdat);
static int set_updatedat(atclient_atkey_metadata *metadata, const char *updatedat);
static void set_ispublic(atclient_atkey_metadata *metadata, const bool ispublic);
static void set_iscached(atclient_atkey_metadata *metadata, const bool iscached);
static void set_ttl(atclient_atkey_metadata *metadata, const long ttl);
static void set_ttb(atclient_atkey_metadata *metadata, const long ttb);
static void set_ttr(atclient_atkey_metadata *metadata, const long ttr);
static void set_ccd(atclient_atkey_metadata *metadata, const bool ccd);
static void set_isbinary(atclient_atkey_metadata *metadata, const bool isbinary);
static void set_isencrypted(atclient_atkey_metadata *metadata, const bool isencrypted);
static int set_datasignature(atclient_atkey_metadata *metadata, const char *datasignature);
static int set_sharedkeystatus(atclient_atkey_metadata *metadata, const char *sharedkeystatus);
static int set_sharedkeyenc(atclient_atkey_metadata *metadata, const char *sharedkeyenc);
static int set_pubkeyhash(atclient_atkey_metadata *metadata, const char *pubkeyhash);
static int set_pubkeyalgo(atclient_atkey_metadata *metadata, const char *pubkeyalgo);
static int set_encoding(atclient_atkey_metadata *metadata, const char *encoding);
static int set_enckeyname(atclient_atkey_metadata *metadata, const char *enckeyname);
static int set_encalgo(atclient_atkey_metadata *metadata, const char *encalgo);
static int set_ivnonce(atclient_atkey_metadata *metadata, const char *ivnonce);
static int set_skeenckeyname(atclient_atkey_metadata *metadata, const char *skeenckeyname);
static int set_skeencalgo(atclient_atkey_metadata *metadata, const char *skeencalgo);

void atclient_atkey_metadata_init(atclient_atkey_metadata *metadata) {
  memset(metadata, 0, sizeof(atclient_atkey_metadata));
}

int atclient_atkey_metadata_from_jsonstr(atclient_atkey_metadata *metadata, const char *metadatastr) {
  int ret = 1;

  cJSON *root = cJSON_Parse(metadatastr);
  if (root == NULL) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "cJSON_Parse failed\n");
    goto exit;
  }

  if ((ret = atclient_atkey_metadata_from_cjson_node(metadata, root)) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atclient_atkey_metadata_from_cjson_node: %d\n", ret);
    goto exit;
  }

  ret = 0;
  goto exit;

exit: {
  cJSON_Delete(root);
  return ret;
}
}

int atclient_atkey_metadata_from_cjson_node(atclient_atkey_metadata *metadata, const cJSON *json) {
  int ret = 1;

  if(json == NULL) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "json is NULL\n");
    goto exit;
  }

  if(metadata == NULL) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "metadata is NULL\n");
    goto exit;
  }

  cJSON *createdby = cJSON_GetObjectItem(json, "createdBy");
  if (createdby != NULL) {
    if (createdby->type != cJSON_NULL) {
      if ((ret = set_createdby(metadata, createdby->valuestring)) != 0) {
        atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "set_createdby: %d\n", ret);
        goto exit;
      }
    } else {
      if ((ret = set_createdby(metadata, "null")) != 0) {
        atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "set_createdby: %d\n", ret);
        goto exit;
      }
    }
  }

  cJSON *updatedby = cJSON_GetObjectItem(json, "updatedBy");
  if (updatedby != NULL) {
    if (updatedby->type != cJSON_NULL) {
      if ((ret = set_updatedby(metadata, updatedby->valuestring)) != 0) {
        atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "set_updatedby: %d\n", ret);
        goto exit;
      }
    } else {
      if ((ret = set_updatedby(metadata, "null")) != 0) {
        atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "set_updatedby: %d\n", ret);
        goto exit;
      }
    }
  }

  cJSON *status = cJSON_GetObjectItem(json, "status");
  if (status != NULL) {
    if (status->type != cJSON_NULL) {
      if ((ret = set_status(metadata, status->valuestring)) != 0) {
        atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "set_status: %d\n", ret);
        goto exit;
      }
    } else {
      if ((ret = set_status(metadata, "null")) != 0) {
        atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "set_status: %d\n", ret);
        goto exit;
      }
    }
  }

  cJSON *version = cJSON_GetObjectItem(json, "version");
  if (version != NULL) {
    if (version->type != cJSON_NULL) {
      set_version(metadata, version->valueint);
    } else {
      set_version(metadata, 0);
    }
  }

  cJSON *expiresat = cJSON_GetObjectItem(json, "expiresAt");
  if (expiresat != NULL) {
    if (expiresat->type != cJSON_NULL) {
      if ((ret = set_expiresat(metadata, expiresat->valuestring)) != 0) {
        atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "set_expiresat: %d\n", ret);
        goto exit;
      }
    } else {
      if ((ret = set_expiresat(metadata, "null")) != 0) {
        atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "set_expiresat: %d\n", ret);
        goto exit;
      }
    }
  }

  cJSON *availableat = cJSON_GetObjectItem(json, "availableAt");
  if (availableat != NULL) {
    if (availableat->type != cJSON_NULL) {
      if ((ret = set_availableat(metadata, availableat->valuestring)) != 0) {
        atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "set_availableat: %d\n", ret);
        goto exit;
      }
    } else {
      if ((ret = set_availableat(metadata, "null")) != 0) {
        atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "set_availableat: %d\n", ret);
        goto exit;
      }
    }
  }

  cJSON *refreshat = cJSON_GetObjectItem(json, "refreshAt");
  if (refreshat != NULL) {
    if (refreshat->type != cJSON_NULL) {
      if((ret = set_refreshat(metadata, refreshat->valuestring)) != 0) {
        atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "set_refreshat: %d\n", ret);
        goto exit;
      }
    } else {
      if((ret = set_refreshat(metadata, "null")) != 0) {
        atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "set_refreshat: %d\n", ret);
        goto exit;
      }
    }
  }

  cJSON *createdat = cJSON_GetObjectItem(json, "createdAt");
  if (createdat != NULL) {
    if (createdat->type != cJSON_NULL) {
      if((ret = set_createdat(metadata, createdat->valuestring)) != 0) {
        atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "set_createdat: %d\n", ret);
        goto exit;
      }
    } else {
      if((ret = set_createdat(metadata, "null")) != 0) {
        atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "set_createdat: %d\n", ret);
        goto exit;
      }
    }
  }

  cJSON *updatedat = cJSON_GetObjectItem(json, "updatedAt");
  if (updatedat != NULL) {
    if (updatedat->type != cJSON_NULL) {
      if((ret = set_updatedat(metadata, updatedat->valuestring)) != 0) {
        atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "set_updatedat: %d\n", ret);
        goto exit;
      }
    } else {
      if((ret = set_updatedat(metadata, "null")) != 0) {
        atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "set_updatedat: %d\n", ret);
        goto exit;
      }
    }
  }

  // I don't think this field exists when reading metadata from atServer
  // cJSON *ispublic = cJSON_GetObjectItem(root, "isPublic");
  // if(ispublic != NULL) {
  //   set_ispublic(metadata, ispublic->valueint);
  // }

  // I don't think this field exists when reading metadata from atServer
  // cJSON *iscached = cJSON_GetObjectItem(root, "isCached
  // if(iscached != NULL) {
  //   set_iscached(metadata, iscached->valueint);
  // }

  cJSON *ttl = cJSON_GetObjectItem(json, "ttl");
  if (ttl != NULL) {
    if (ttl->type != cJSON_NULL) {
      set_ttl(metadata, ttl->valueint);
    } else {
      set_ttl(metadata, 0);
    }
  }

  cJSON *ttb = cJSON_GetObjectItem(json, "ttb");
  if (ttb != NULL) {
    if (ttb->type != cJSON_NULL) {
      set_ttb(metadata, ttb->valueint);
    } else {
      set_ttb(metadata, 0);
    }
  }

  cJSON *ttr = cJSON_GetObjectItem(json, "ttr");
  if (ttr != NULL) {
    if (ttr->type != cJSON_NULL) {
      set_ttr(metadata, ttr->valueint);
    } else {
      set_ttr(metadata, 0);
    }
  }

  cJSON *ccd = cJSON_GetObjectItem(json, "ccd");
  if (ccd != NULL) {
    if (ccd->type != cJSON_NULL) {
      set_ccd(metadata, ccd->valueint);
    } else {
      set_ccd(metadata, 0);
    }
  }

  cJSON *isbinary = cJSON_GetObjectItem(json, "isBinary");
  if (isbinary != NULL) {
    if (isbinary->type != cJSON_NULL) {
      set_isbinary(metadata, isbinary->valueint);
    } else {
      set_isbinary(metadata, 0);
    }
  }

  cJSON *isencrypted = cJSON_GetObjectItem(json, "isEncrypted");
  if (isencrypted != NULL) {
    if (isencrypted->type != cJSON_NULL) {
      set_isencrypted(metadata, isencrypted->valueint);
    } else {
      set_isencrypted(metadata, 0);
    }
  }

  cJSON *datasignature = cJSON_GetObjectItem(json, "dataSignature");
  if (datasignature != NULL) {
    if (datasignature->type != cJSON_NULL) {
      if((ret = set_datasignature(metadata, datasignature->valuestring)) != 0) {
        atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "set_datasignature: %d\n", ret);
        goto exit;
      }
    } else {
      if((ret = set_datasignature(metadata, "null")) != 0) {
        atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "set_datasignature: %d\n", ret);
        goto exit;
      }
    }
  }

  cJSON *sharedkeystatus = cJSON_GetObjectItem(json, "sharedKeyStatus");
  if (sharedkeystatus != NULL) {
    if (sharedkeystatus->type != cJSON_NULL) {
      if((ret = set_sharedkeystatus(metadata, sharedkeystatus->valuestring)) != 0) {
        atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "set_sharedkeystatus: %d\n", ret);
        goto exit;
      }
    } else {
      if((ret = set_sharedkeystatus(metadata, "null")) != 0) {
        atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "set_sharedkeystatus: %d\n", ret);
        goto exit;
      }
    }
  }

  cJSON *sharedkeyenc = cJSON_GetObjectItem(json, "sharedKeyEnc");
  if (sharedkeyenc != NULL) {
    if (sharedkeyenc->type != cJSON_NULL) {
      if((ret = set_sharedkeyenc(metadata, sharedkeyenc->valuestring)) != 0) {
        atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "set_sharedkeyenc: %d\n", ret);
        goto exit;
      }
    } else {
      if((ret = set_sharedkeyenc(metadata, "null")) != 0) {
        atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "set_sharedkeyenc: %d\n", ret);
        goto exit;
      }
    }
  }

  cJSON *pubkeyhash = cJSON_GetObjectItem(json, "pubKeyHash");
  if (pubkeyhash != NULL) {
    if (pubkeyhash->type != cJSON_NULL) {
      if((ret = set_pubkeyhash(metadata, pubkeyhash->valuestring)) != 0) {
        atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "set_pubkeyhash: %d\n", ret);
        goto exit;
      }
    } else {
      if((ret = set_pubkeyhash(metadata, "null")) != 0) {
        atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "set_pubkeyhash: %d\n", ret);
        goto exit;
      }
    }
  }

  cJSON *pubkeyalgo = cJSON_GetObjectItem(json, "pubKeyAlgo");
  if (pubkeyalgo != NULL) {
    if (pubkeyalgo->type != cJSON_NULL) {
      if((ret = set_pubkeyalgo(metadata, pubkeyalgo->valuestring)) != 0) {
        atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "set_pubkeyalgo: %d\n", ret);
        goto exit;
      }
    } else {
      if((ret = set_pubkeyalgo(metadata, "null")) != 0) {
        atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "set_pubkeyalgo: %d\n", ret);
        goto exit;
      }
    }
  }

  cJSON *encoding = cJSON_GetObjectItem(json, "encoding");
  if (encoding != NULL) {
    if (encoding->type != cJSON_NULL) {
      if((ret = set_encoding(metadata, encoding->valuestring)) != 0) {
        atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "set_encoding: %d\n", ret);
        goto exit;
      }
    } else {
      if((ret = set_encoding(metadata, "null")) != 0) {
        atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "set_encoding: %d\n", ret);
        goto exit;
      }
    }
  }

  cJSON *enckeyname = cJSON_GetObjectItem(json, "encKeyName");
  if (enckeyname != NULL) {
    if (enckeyname->type != cJSON_NULL) {
      if((ret = set_enckeyname(metadata, enckeyname->valuestring)) != 0) {
        atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "set_enckeyname: %d\n", ret);
        goto exit;
      }
    } else {
      if((ret = set_enckeyname(metadata, "null")) != 0) {
        atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "set_enckeyname: %d\n", ret);
        goto exit;
      }
    }
  }

  cJSON *encalgo = cJSON_GetObjectItem(json, "encAlgo");
  if (encalgo != NULL) {
    if (encalgo->type != cJSON_NULL) {
      if((ret = set_encalgo(metadata, encalgo->valuestring)) != 0) {
        atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "set_encalgo: %d\n", ret);
        goto exit;
      }
    } else {
      if((ret = set_encalgo(metadata, "null")) != 0) {
        atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "set_encalgo: %d\n", ret);
        goto exit;
      }
    }
  }

  cJSON *ivnonce = cJSON_GetObjectItem(json, "ivNonce");
  if (ivnonce != NULL) {
    if (ivnonce->type != cJSON_NULL) {
      if((ret = set_ivnonce(metadata, ivnonce->valuestring)) != 0) {
        atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "set_ivnonce: %d\n", ret);
        goto exit;
      }
    } else {
      if((ret = set_ivnonce(metadata, "null")) != 0) {
        atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "set_ivnonce: %d\n", ret);
        goto exit;
      }
    }
  }

  cJSON *skeenckeyname = cJSON_GetObjectItem(json, "skeEncKeyName");
  if (skeenckeyname != NULL) {
    if (skeenckeyname->type != cJSON_NULL) {
      if((ret = set_skeenckeyname(metadata, skeenckeyname->valuestring)) != 0) {
        atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "set_skeenckeyname: %d\n", ret);
        goto exit;
      }
    } else {
      if((ret = set_skeenckeyname(metadata, "null")) != 0) {
        atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "set_skeenckeyname: %d\n", ret);
        goto exit;
      }
    }
  }

  cJSON *skeencalgo = cJSON_GetObjectItem(json, "skeEncAlgo");
  if (skeencalgo != NULL) {
    if (skeencalgo->type != cJSON_NULL) {
      if((ret = set_skeencalgo(metadata, skeencalgo->valuestring)) != 0) {
        atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "set_skeencalgo: %d\n", ret);
        goto exit;
      }
    } else {
      if((ret = set_skeencalgo(metadata, "null")) != 0) {
        atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "set_skeencalgo: %d\n", ret);
        goto exit;
      }
    }
  }

  ret = 0;
  goto exit;
exit: { return ret; }
}

int atclient_atkey_metadata_to_jsonstr(const atclient_atkey_metadata *metadata, char **metadatastr) {
  int ret = 1;

  if (metadata == NULL) {
    ret = 1;
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "metadata is NULL\n");
    return ret;
  }

  if (metadatastr == NULL) {
    ret = 1;
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "metadatastr is NULL\n");
    return ret;
  }

  char *jsonstr = NULL;
  cJSON *root = cJSON_CreateObject();
  if (root == NULL) {
    ret = 1;
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "cJSON_CreateObject failed\n");
    goto exit;
  }

  if (atclient_atkey_metadata_is_createdby_initialized(metadata)) {
    cJSON_AddStringToObject(root, "createdBy", metadata->createdby);
  }

  if (atclient_atkey_metadata_is_updatedby_initialized(metadata)) {
    cJSON_AddStringToObject(root, "updatedBy", metadata->updatedby);
  }

  if (atclient_atkey_metadata_is_status_initialized(metadata)) {
    cJSON_AddStringToObject(root, "status", metadata->status);
  }

  if (atclient_atkey_metadata_is_version_initialized(metadata)) {
    cJSON_AddNumberToObject(root, "version", metadata->version);
  }

  if (atclient_atkey_metadata_is_expiresat_initialized(metadata)) {
    cJSON_AddStringToObject(root, "expiresAt", metadata->expiresat);
  }

  if (atclient_atkey_metadata_is_availableat_initialized(metadata)) {
    cJSON_AddStringToObject(root, "availableAt", metadata->availableat);
  }

  if (atclient_atkey_metadata_is_refreshat_initialized(metadata)) {
    cJSON_AddStringToObject(root, "refreshAt", metadata->refreshat);
  }

  if (atclient_atkey_metadata_is_createdat_initialized(metadata)) {
    cJSON_AddStringToObject(root, "createdAt", metadata->createdat);
  }

  if (atclient_atkey_metadata_is_updatedat_initialized(metadata)) {
    cJSON_AddStringToObject(root, "updatedAt", metadata->updatedat);
  }

  if (atclient_atkey_metadata_is_ispublic_initialized(metadata)) {
    cJSON_AddBoolToObject(root, "isPublic", metadata->ispublic);
  }

  if (atclient_atkey_metadata_is_iscached_initialized(metadata)) {
    cJSON_AddBoolToObject(root, "isCached", metadata->iscached);
  }

  if (atclient_atkey_metadata_is_ttl_initialized(metadata)) {
    cJSON_AddNumberToObject(root, "ttl", metadata->ttl);
  }

  if (atclient_atkey_metadata_is_ttb_initialized(metadata)) {
    cJSON_AddNumberToObject(root, "ttb", metadata->ttb);
  }

  if (atclient_atkey_metadata_is_ttr_initialized(metadata)) {
    cJSON_AddNumberToObject(root, "ttr", metadata->ttr);
  }

  if (atclient_atkey_metadata_is_ccd_initialized(metadata)) {
    cJSON_AddBoolToObject(root, "ccd", metadata->ccd);
  }

  if (atclient_atkey_metadata_is_isbinary_initialized(metadata)) {
    cJSON_AddBoolToObject(root, "isBinary", metadata->isbinary);
  }

  if (atclient_atkey_metadata_is_isencrypted_initialized(metadata)) {
    cJSON_AddBoolToObject(root, "isEncrypted", metadata->isencrypted);
  }

  if (atclient_atkey_metadata_is_datasignature_initialized(metadata)) {
    cJSON_AddStringToObject(root, "dataSignature", metadata->datasignature);
  }

  if (atclient_atkey_metadata_is_sharedkeystatus_initialized(metadata)) {
    cJSON_AddStringToObject(root, "sharedKeyStatus", metadata->sharedkeystatus);
  }

  if (atclient_atkey_metadata_is_sharedkeyenc_initialized(metadata)) {
    cJSON_AddStringToObject(root, "sharedKeyEnc", metadata->sharedkeyenc);
  }

  if (atclient_atkey_metadata_is_pubkeyhash_initialized(metadata)) {
    cJSON_AddStringToObject(root, "pubKeyHash", metadata->pubkeyhash);
  }

  if (atclient_atkey_metadata_is_pubkeyalgo_initialized(metadata)) {
    cJSON_AddStringToObject(root, "pubKeyAlgo", metadata->pubkeyalgo);
  }

  if (atclient_atkey_metadata_is_encoding_initialized(metadata)) {
    cJSON_AddStringToObject(root, "encoding", metadata->encoding);
  }

  if (atclient_atkey_metadata_is_enckeyname_initialized(metadata)) {
    cJSON_AddStringToObject(root, "encKeyName", metadata->enckeyname);
  }

  if (atclient_atkey_metadata_is_encalgo_initialized(metadata)) {
    cJSON_AddStringToObject(root, "encAlgo", metadata->encalgo);
  }

  if (atclient_atkey_metadata_is_ivnonce_initialized(metadata)) {
    cJSON_AddStringToObject(root, "ivNonce", metadata->ivnonce);
  }

  if (atclient_atkey_metadata_is_skeenckeyname_initialized(metadata)) {
    cJSON_AddStringToObject(root, "skeEncKeyName", metadata->skeenckeyname);
  }

  if (atclient_atkey_metadata_is_skeencalgo_initialized(metadata)) {
    cJSON_AddStringToObject(root, "skeEncAlgo", metadata->skeencalgo);
  }

  jsonstr = cJSON_Print(root);
  if (jsonstr == NULL) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "cJSON_Print failed\n");
    goto exit;
  }

  const size_t metadatastrsize = strlen(jsonstr) + 1;
  *metadatastr = (char *)malloc(sizeof(char) * metadatastrsize);
  if (*metadatastr == NULL) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "malloc failed\n");
    goto exit;
  }
  memcpy(*metadatastr, jsonstr, strlen(jsonstr));
  (*metadatastr)[strlen(jsonstr)] = '\0';

  ret = 0;
  goto exit;
exit: {
  free(jsonstr);
  cJSON_Delete(root);
  return ret;
}
}

size_t atclient_atkey_metadata_protocol_strlen(const atclient_atkey_metadata *metadata) {
  long len = 0;
  if (atclient_atkey_metadata_is_ttl_initialized(metadata)) {
    len += atclient_atkey_metadata_ttl_strlen(metadata);
  }

  if (atclient_atkey_metadata_is_ttb_initialized(metadata)) {
    len += atclient_atkey_metadata_ttb_strlen(metadata);
  }

  if (atclient_atkey_metadata_is_ttr_initialized(metadata)) {
    len += atclient_atkey_metadata_ttr_strlen(metadata);
  }

  if (atclient_atkey_metadata_is_ccd_initialized(metadata)) {
    len += atclient_atkey_metadata_ccd_strlen(metadata);
  }

  if (atclient_atkey_metadata_is_isbinary_initialized(metadata)) {
    len += atclient_atkey_metadata_isbinary_strlen(metadata);
  }

  if (atclient_atkey_metadata_is_isencrypted_initialized(metadata)) {
    len += atclient_atkey_metadata_isencrypted_strlen(metadata);
  }

  if (atclient_atkey_metadata_is_datasignature_initialized(metadata)) {
    len += atclient_atkey_metadata_datasignature_strlen(metadata);
  }

  if (atclient_atkey_metadata_is_sharedkeystatus_initialized(metadata)) {
    len += atclient_atkey_metadata_sharedkeystatus_strlen(metadata);
  }

  if (atclient_atkey_metadata_is_sharedkeyenc_initialized(metadata)) {
    len += atclient_atkey_metadata_sharedkeyenc_strlen(metadata);
  }

  if (atclient_atkey_metadata_is_pubkeyhash_initialized(metadata)) {
    len += atclient_atkey_metadata_pubkeyhash_strlen(metadata);
  }

  if (atclient_atkey_metadata_is_pubkeyalgo_initialized(metadata)) {
    len += atclient_atkey_metadata_pubkeyalgo_strlen(metadata);
  }

  if (atclient_atkey_metadata_is_encoding_initialized(metadata)) {
    len += atclient_atkey_metadata_encoding_strlen(metadata);
  }

  if (atclient_atkey_metadata_is_enckeyname_initialized(metadata)) {
    len += atclient_atkey_metadata_enckeyname_strlen(metadata);
  }

  if (atclient_atkey_metadata_is_encalgo_initialized(metadata)) {
    len += atclient_atkey_metadata_encalgo_strlen(metadata);
  }

  if (atclient_atkey_metadata_is_ivnonce_initialized(metadata)) {
    len += atclient_atkey_metadata_ivnonce_strlen(metadata);
  }

  if (atclient_atkey_metadata_is_skeenckeyname_initialized(metadata)) {
    len += atclient_atkey_metadata_skeenckeyname_strlen(metadata);
  }

  if (atclient_atkey_metadata_is_skeencalgo_initialized(metadata)) {
    len += atclient_atkey_metadata_skeencalgo_strlen(metadata);
  }

  return len;
}

size_t atclient_atkey_metadata_ttl_strlen(const atclient_atkey_metadata *metadata) {
  return 5 // :ttl:
         + long_strlen(metadata->ttl);
}

size_t atclient_atkey_metadata_ttb_strlen(const atclient_atkey_metadata *metadata) {
  return 5 // :ttb:
         + long_strlen(metadata->ttb);
}

size_t atclient_atkey_metadata_ttr_strlen(const atclient_atkey_metadata *metadata) {
  return 5 // :ttr:
         + long_strlen(metadata->ttr);
}

size_t atclient_atkey_metadata_ccd_strlen(const atclient_atkey_metadata *metadata) {
  if (metadata->ccd) {
    return 9; // :ccd:true
  } else {
    return 10; // :ccd:false
  }
  return 0;
}

size_t atclient_atkey_metadata_isbinary_strlen(const atclient_atkey_metadata *metadata) {
  if (metadata->isbinary) {
    return 14; // :isBinary:true
  } else {
    return 15; // :isBinary:false
  }
}

size_t atclient_atkey_metadata_isencrypted_strlen(const atclient_atkey_metadata *metadata) {
  if (metadata->isencrypted) {
    return 17; // :isEncrypted:true
  } else {
    return 18; // :isEncrypted:false
  }
  return 0;
}

size_t atclient_atkey_metadata_datasignature_strlen(const atclient_atkey_metadata *metadata) {
  // :dataSignature:<signature>
  return strlen(":dataSignature:") + strlen(metadata->datasignature);
}

size_t atclient_atkey_metadata_sharedkeystatus_strlen(const atclient_atkey_metadata *metadata) {
  return strlen(":sharedKeyStatus:") + strlen(metadata->sharedkeystatus);
}

size_t atclient_atkey_metadata_sharedkeyenc_strlen(const atclient_atkey_metadata *metadata) {
  return strlen(":sharedKeyEnc:") + strlen(metadata->sharedkeyenc);
}

size_t atclient_atkey_metadata_pubkeyhash_strlen(const atclient_atkey_metadata *metadata) {
  return strlen(":hash:") + strlen(metadata->pubkeyhash);
}

size_t atclient_atkey_metadata_pubkeyalgo_strlen(const atclient_atkey_metadata *metadata) {
  return strlen(":algo:") + strlen(metadata->pubkeyalgo);
}

size_t atclient_atkey_metadata_encoding_strlen(const atclient_atkey_metadata *metadata) {
  return strlen(":encoding:") + strlen(metadata->encoding);
}

size_t atclient_atkey_metadata_enckeyname_strlen(const atclient_atkey_metadata *metadata) {
  return strlen(":encKeyName:") + strlen(metadata->enckeyname);
}

size_t atclient_atkey_metadata_encalgo_strlen(const atclient_atkey_metadata *metadata) {
  return strlen(":encAlgo:") + strlen(metadata->encalgo);
}

size_t atclient_atkey_metadata_ivnonce_strlen(const atclient_atkey_metadata *metadata) {
  return strlen(":ivNonce:") + strlen(metadata->ivnonce);
}

size_t atclient_atkey_metadata_skeenckeyname_strlen(const atclient_atkey_metadata *metadata) {
  return strlen(":skeEncKeyName:") + strlen(metadata->skeenckeyname);
}

size_t atclient_atkey_metadata_skeencalgo_strlen(const atclient_atkey_metadata *metadata) {
  return strlen(":skeEncAlgo:") + strlen(metadata->skeencalgo);
}

int atclient_atkey_metadata_to_protocol_str(const atclient_atkey_metadata *metadata, char **metadatastr) {
  int ret = 1;

  if (metadata == NULL) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "metadata is NULL\n");
    goto exit;
  }

  if (metadatastr == NULL) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "metadatastr is NULL\n");
    goto exit;
  }

  const size_t metadatastrsize = atclient_atkey_metadata_protocol_strlen(metadata) + 1;
  const size_t expected_metadatastr_len = metadatastrsize - 1;
  size_t pos = 0;

  if ((*metadatastr = malloc(sizeof(char) * metadatastrsize)) == NULL) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "malloc failed\n");
    goto exit;
  }
  memset(*metadatastr, 0, sizeof(char) * metadatastrsize);

  if (atclient_atkey_metadata_is_ttl_initialized(metadata)) {
    sprintf(*metadatastr + pos, ":ttl:%ld", metadata->ttl);
    pos += 5 + long_strlen(metadata->ttl);
  }

  if (atclient_atkey_metadata_is_ttb_initialized(metadata)) {
    sprintf(*metadatastr + pos, ":ttb:%ld", metadata->ttb);
    pos += 5 + long_strlen(metadata->ttb);
  }

  if (atclient_atkey_metadata_is_ttr_initialized(metadata)) {
    sprintf(*metadatastr + pos, ":ttr:%ld", metadata->ttr);
    pos += 5 + long_strlen(metadata->ttr);
  }

  if (atclient_atkey_metadata_is_ccd_initialized(metadata)) {
    if (metadata->ccd) {
      sprintf(*metadatastr + pos, ":ccd:true");
      pos += 9;
    } else {
      sprintf(metadatastr + pos, ":ccd:false");
      pos += 10;
    }
  }

  if (atclient_atkey_metadata_is_isbinary_initialized(metadata)) {
    if (metadata->isbinary) {
      sprintf(*metadatastr + pos, ":isBinary:true");
      pos += 14;
    } else {
      sprintf(*metadatastr + pos, ":isBinary:false");
      pos += 15;
    }
  }

  if (atclient_atkey_metadata_is_isencrypted_initialized(metadata)) {
    if (metadata->isencrypted) {
      sprintf(*metadatastr + pos, ":isEncrypted:true");
      pos += 17;
    } else {
      sprintf(*metadatastr + pos, ":isEncrypted:false");
      pos += 18;
    }
  }

  if (atclient_atkey_metadata_is_datasignature_initialized(metadata)) {
    sprintf(*metadatastr + pos, ":dataSignature:%s", metadata->datasignature);
    pos += strlen(":dataSignature:") + strlen(metadata->datasignature);
  }

  if (atclient_atkey_metadata_is_sharedkeystatus_initialized(metadata)) {
    sprintf(*metadatastr + pos, ":sharedKeyStatus:%s", metadata->sharedkeystatus);
    pos += strlen(":sharedKeyStatus:") + strlen(metadata->sharedkeystatus);
  }

  if (atclient_atkey_metadata_is_sharedkeyenc_initialized(metadata)) {
    sprintf(*metadatastr + pos, ":sharedKeyEnc:%s", metadata->sharedkeyenc);
    pos += strlen(":sharedKeyEnc:") + strlen(metadata->sharedkeyenc);
  }

  if (atclient_atkey_metadata_is_pubkeyhash_initialized(metadata)) {
    sprintf(*metadatastr + pos, ":hash:%s", metadata->pubkeyhash);
    pos += strlen(":hash:") + strlen(metadata->pubkeyhash);
  }

  if (atclient_atkey_metadata_is_pubkeyalgo_initialized(metadata)) {
    sprintf(*metadatastr + pos, ":algo:%s", metadata->pubkeyalgo);
    pos += strlen(":algo:") + strlen(metadata->pubkeyalgo);
  }

  if (atclient_atkey_metadata_is_encoding_initialized(metadata)) {
    sprintf(*metadatastr + pos, ":encoding:%s", metadata->encoding);
    pos += strlen(":encoding:") + strlen(metadata->encoding);
  }

  if (atclient_atkey_metadata_is_enckeyname_initialized(metadata)) {
    sprintf(*metadatastr + pos, ":encKeyName:%s", metadata->enckeyname);
    pos += strlen(":encKeyName:") + strlen(metadata->enckeyname);
  }

  if (atclient_atkey_metadata_is_encalgo_initialized(metadata)) {
    sprintf(*metadatastr + pos, ":encAlgo:%s", metadata->encalgo);
    pos += strlen(":encAlgo:") + strlen(metadata->encalgo);
  }

  if (atclient_atkey_metadata_is_ivnonce_initialized(metadata)) {
    sprintf(*metadatastr + pos, ":ivNonce:%s", metadata->ivnonce);
    pos += strlen(":ivNonce:") + strlen(metadata->ivnonce);
  }

  if (atclient_atkey_metadata_is_skeenckeyname_initialized(metadata)) {
    sprintf(*metadatastr + pos, ":skeEncKeyName:%s", metadata->skeenckeyname);
    pos += strlen(":skeEncKeyName:") + strlen(metadata->skeenckeyname);
  }

  if (atclient_atkey_metadata_is_skeencalgo_initialized(metadata)) {
    sprintf(*metadatastr + pos, ":skeEncAlgo:%s", metadata->skeencalgo);
    pos += strlen(":skeEncAlgo:") + strlen(metadata->skeencalgo);
  }

  if (strlen(*metadatastr) != (expected_metadatastr_len)) {
    ret = 1;
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "metadatastr length mismatch: %lu != %lu\n", strlen(*metadatastr),
                 (expected_metadatastr_len));
    goto exit;
  }

  ret = 0;
  goto exit;
exit: { return ret; }
}

bool atclient_atkey_metadata_is_createdby_initialized(const atclient_atkey_metadata *metadata) {
  return is_createdby_initialized(metadata);
}

bool atclient_atkey_metadata_is_updatedby_initialized(const atclient_atkey_metadata *metadata) {
  return is_updatedby_initialized(metadata);
}

bool atclient_atkey_metadata_is_status_initialized(const atclient_atkey_metadata *metadata) {
  return is_status_initialized(metadata);
}

bool atclient_atkey_metadata_is_version_initialized(const atclient_atkey_metadata *metadata) {
  return is_version_initialized(metadata);
}

bool atclient_atkey_metadata_is_availableat_initialized(const atclient_atkey_metadata *metadata) {
  return is_availableat_initialized(metadata);
}

bool atclient_atkey_metadata_is_expiresat_initialized(const atclient_atkey_metadata *metadata) {
  return is_expiresat_initialized(metadata);
}

bool atclient_atkey_metadata_is_refreshat_initialized(const atclient_atkey_metadata *metadata) {
  return is_refreshat_initialized(metadata);
}

bool atclient_atkey_metadata_is_createdat_initialized(const atclient_atkey_metadata *metadata) {
  return is_createdat_initialized(metadata);
}

bool atclient_atkey_metadata_is_updatedat_initialized(const atclient_atkey_metadata *metadata) {
  return is_updatedat_initialized(metadata);
}

bool atclient_atkey_metadata_is_ispublic_initialized(const atclient_atkey_metadata *metadata) {
  return is_ispublic_initialized(metadata);
}

bool atclient_atkey_metadata_is_iscached_initialized(const atclient_atkey_metadata *metadata) {
  return is_iscached_initialized(metadata);
}

bool atclient_atkey_metadata_is_ttl_initialized(const atclient_atkey_metadata *metadata) {
  return is_ttl_initialized(metadata);
}

bool atclient_atkey_metadata_is_ttb_initialized(const atclient_atkey_metadata *metadata) {
  return is_ttb_initialized(metadata);
}

bool atclient_atkey_metadata_is_ttr_initialized(const atclient_atkey_metadata *metadata) {
  return is_ttr_initialized(metadata);
}

bool atclient_atkey_metadata_is_ccd_initialized(const atclient_atkey_metadata *metadata) {
  return is_ccd_initialized(metadata);
}

bool atclient_atkey_metadata_is_isbinary_initialized(const atclient_atkey_metadata *metadata) {
  return is_isbinary_initialized(metadata);
}

bool atclient_atkey_metadata_is_isencrypted_initialized(const atclient_atkey_metadata *metadata) {
  return is_isencrypted_initialized(metadata);
}

bool atclient_atkey_metadata_is_datasignature_initialized(const atclient_atkey_metadata *metadata) {
  return is_datasignature_initialized(metadata);
}

bool atclient_atkey_metadata_is_sharedkeystatus_initialized(const atclient_atkey_metadata *metadata) {
  return is_sharedkeystatus_initialized(metadata);
}

bool atclient_atkey_metadata_is_sharedkeyenc_initialized(const atclient_atkey_metadata *metadata) {
  return is_sharedkeyenc_initialized(metadata);
}

bool atclient_atkey_metadata_is_pubkeyhash_initialized(const atclient_atkey_metadata *metadata) {
  return is_pubkeyhash_initialized(metadata);
}

bool atclient_atkey_metadata_is_pubkeyalgo_initialized(const atclient_atkey_metadata *metadata) {
  return is_pubkeyalgo_initialized(metadata);
}

bool atclient_atkey_metadata_is_encoding_initialized(const atclient_atkey_metadata *metadata) {
  return is_encoding_initialized(metadata);
}

bool atclient_atkey_metadata_is_enckeyname_initialized(const atclient_atkey_metadata *metadata) {
  return is_enckeyname_initialized(metadata);
}

bool atclient_atkey_metadata_is_encalgo_initialized(const atclient_atkey_metadata *metadata) {
  return is_encalgo_initialized(metadata);
}

bool atclient_atkey_metadata_is_ivnonce_initialized(const atclient_atkey_metadata *metadata) {
  return is_ivnonce_initialized(metadata);
}

bool atclient_atkey_metadata_is_skeenckeyname_initialized(const atclient_atkey_metadata *metadata) {
  return is_skeenckeyname_initialized(metadata);
}

bool atclient_atkey_metadata_is_skeencalgo_initialized(const atclient_atkey_metadata *metadata) {
  return is_skeencalgo_initialized(metadata);
}

int atclient_atkey_metadata_set_ispublic(atclient_atkey_metadata *metadata, const bool ispublic) {
  if (is_ispublic_initialized(metadata)) {
    unset_ispublic(metadata);
  }
  set_ispublic(metadata, ispublic);
  return 0;
}

int atclient_atkey_metadata_set_iscached(atclient_atkey_metadata *metadata, const bool iscached) {
  if (is_iscached_initialized(metadata)) {
    unset_iscached(metadata);
  }
  set_iscached(metadata, iscached);
  return 0;
}

int atclient_atkey_metadata_set_ttl(atclient_atkey_metadata *metadata, const long ttl) {
  if (is_ttl_initialized(metadata)) {
    unset_ttl(metadata);
  }
  set_ttl(metadata, ttl);
  return 0;
}

int atclient_atkey_metadata_set_ttb(atclient_atkey_metadata *metadata, const long ttb) {
  if (is_ttb_initialized(metadata)) {
    unset_ttb(metadata);
  }
  set_ttb(metadata, ttb);
  return 0;
}

int atclient_atkey_metadata_set_ttr(atclient_atkey_metadata *metadata, const long ttr) {
  if (is_ttr_initialized(metadata)) {
    unset_ttr(metadata);
  }
  set_ttr(metadata, ttr);
  return 0;
}

int atclient_atkey_metadata_set_ccd(atclient_atkey_metadata *metadata, const bool ccd) {
  if (is_ccd_initialized(metadata)) {
    unset_ccd(metadata);
  }
  set_ccd(metadata, ccd);
  return 0;
}

int atclient_atkey_metadata_set_isbinary(atclient_atkey_metadata *metadata, const bool isbinary) {
  if (is_isbinary_initialized(metadata)) {
    unset_isbinary(metadata);
  }
  set_isbinary(metadata, isbinary);
  return 0;
}

int atclient_atkey_metadata_set_isencrypted(atclient_atkey_metadata *metadata, const bool isencrypted) {
  if (is_isencrypted_initialized(metadata)) {
    unset_isencrypted(metadata);
  }
  set_isencrypted(metadata, isencrypted);
  return 0;
}

int atclient_atkey_metadata_set_datasignature(atclient_atkey_metadata *metadata, const char *datasignature) {
  int ret = 1;
  if (is_datasignature_initialized(metadata)) {
    unset_datasignature(metadata);
  }
  if ((ret = set_datasignature(metadata, datasignature)) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "set_datasignature failed\n");
    goto exit;
  }
  ret = 0;
  goto exit;
exit: { return ret; }
}

int atclient_atkey_metadata_set_sharedkeystatus(atclient_atkey_metadata *metadata, const char *sharedkeystatus) {
  int ret = 1;
  if (is_sharedkeystatus_initialized(metadata)) {
    unset_sharedkeystatus(metadata);
  }
  if ((ret = set_sharedkeystatus(metadata, sharedkeystatus)) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "set_sharedkeystatus failed\n");
    goto exit;
  }
  ret = 0;
  goto exit;
exit: { return ret; }
}

int atclient_atkey_metadata_set_sharedkeyenc(atclient_atkey_metadata *metadata, const char *sharedkeyenc) {
  int ret = 1;
  if (is_sharedkeyenc_initialized(metadata)) {
    unset_sharedkeyenc(metadata);
  }
  if ((ret = set_sharedkeyenc(metadata, sharedkeyenc)) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "set_sharedkeyenc failed\n");
    goto exit;
  }
  ret = 0;
  goto exit;
exit: { return ret; }
}

int atclient_atkey_metadata_set_pubkeyhash(atclient_atkey_metadata *metadata, const char *pubkeyhash) {
  int ret = 1;
  if (is_pubkeyhash_initialized(metadata)) {
    unset_pubkeyhash(metadata);
  }
  if ((ret = set_pubkeyhash(metadata, pubkeyhash)) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "set_pubkeyhash failed\n");
    goto exit;
  }
  ret = 0;
  goto exit;
exit: { return ret; }
}

int atclient_atkey_metadata_set_pubkeyalgo(atclient_atkey_metadata *metadata, const char *pubkeyalgo) {
  int ret = 1;
  if (is_pubkeyalgo_initialized(metadata)) {
    unset_pubkeyalgo(metadata);
  }
  if ((ret = set_pubkeyalgo(metadata, pubkeyalgo)) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "set_pubkeyalgo failed\n");
    goto exit;
  }
  ret = 0;
  goto exit;
exit: { return ret; }
}

int atclient_atkey_metadata_set_encoding(atclient_atkey_metadata *metadata, const char *encoding) {
  int ret = 1;
  if (is_encoding_initialized(metadata)) {
    unset_encoding(metadata);
  }

  if ((ret = set_encoding(metadata, encoding)) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "set_encoding failed\n");
    goto exit;
  }
  ret = 0;
  goto exit;
exit: { return ret; }
}

int atclient_atkey_metadata_set_enckeyname(atclient_atkey_metadata *metadata, const char *enckeyname) {
  int ret = 1;
  if (is_enckeyname_initialized(metadata)) {
    unset_enckeyname(metadata);
  }
  if ((ret = set_enckeyname(metadata, enckeyname)) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "set_enckeyname failed\n");
    goto exit;
  }
  ret = 0;
  goto exit;
exit: { return ret; }
}

int atclient_atkey_metadata_set_encalgo(atclient_atkey_metadata *metadata, const char *encalgo) {
  int ret = 1;
  if (is_encalgo_initialized(metadata)) {
    unset_encalgo(metadata);
  }
  if ((ret = set_encalgo(metadata, encalgo)) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "set_encalgo failed\n");
    goto exit;
  }
  ret = 0;
  goto exit;
exit: { return ret; }
}

int atclient_atkey_metadata_set_ivnonce(atclient_atkey_metadata *metadata, const char *ivnonce) {
  int ret = 1;
  if (is_ivnonce_initialized(metadata)) {
    unset_ivnonce(metadata);
  }
  if ((ret = set_ivnonce(metadata, ivnonce)) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "set_ivnonce failed\n");
    goto exit;
  }
  ret = 0;
  goto exit;
exit: { return ret; }
}

int atclient_atkey_metadata_set_skeenckeyname(atclient_atkey_metadata *metadata, const char *skeenckeyname) {
  int ret = 1;
  if (is_skeenckeyname_initialized(metadata)) {
    unset_skeenckeyname(metadata);
  }
  if ((ret = set_skeenckeyname(metadata, skeenckeyname)) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "set_skeenckeyname failed\n");
    goto exit;
  }
  ret = 0;
  goto exit;
exit: { return ret; }
}

int atclient_atkey_metadata_set_skeencalgo(atclient_atkey_metadata *metadata, const char *skeencalgo) {
  int ret = 1;
  if (is_skeencalgo_initialized(metadata)) {
    unset_skeencalgo(metadata);
  }
  if ((ret = set_skeencalgo(metadata, skeencalgo)) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "set_skeencalgo failed\n");
    goto exit;
  }
  ret = 0;
  goto exit;
exit: { return ret; }
}

void atclient_atkey_metadata_free(atclient_atkey_metadata *metadata) {
  if (is_createdby_initialized(metadata)) {
    unset_createdby(metadata);
  }

  if (is_updatedby_initialized(metadata)) {
    unset_updatedby(metadata);
  }

  if (is_status_initialized(metadata)) {
    unset_status(metadata);
  }

  if (is_version_initialized(metadata)) {
    unset_version(metadata);
  }

  if (is_expiresat_initialized(metadata)) {
    unset_expiresat(metadata);
  }

  if (is_availableat_initialized(metadata)) {
    unset_availableat(metadata);
  }

  if (is_refreshat_initialized(metadata)) {
    unset_refreshat(metadata);
  }

  if (is_createdat_initialized(metadata)) {
    unset_createdat(metadata);
  }

  if (is_updatedat_initialized(metadata)) {
    unset_updatedat(metadata);
  }

  if (is_ispublic_initialized(metadata)) {
    unset_ispublic(metadata);
  }

  if (is_iscached_initialized(metadata)) {
    unset_iscached(metadata);
  }

  if (is_ttl_initialized(metadata)) {
    unset_ttl(metadata);
  }

  if (is_ttb_initialized(metadata)) {
    unset_ttb(metadata);
  }

  if (is_ttr_initialized(metadata)) {
    unset_ttr(metadata);
  }

  if (is_ccd_initialized(metadata)) {
    unset_ccd(metadata);
  }

  if (is_isbinary_initialized(metadata)) {
    unset_isbinary(metadata);
  }

  if (is_isencrypted_initialized(metadata)) {
    unset_isencrypted(metadata);
  }

  if (is_datasignature_initialized(metadata)) {
    unset_datasignature(metadata);
  }

  if (is_sharedkeystatus_initialized(metadata)) {
    unset_sharedkeystatus(metadata);
  }

  if (is_sharedkeyenc_initialized(metadata)) {
    unset_sharedkeyenc(metadata);
  }

  if (is_pubkeyhash_initialized(metadata)) {
    unset_pubkeyhash(metadata);
  }

  if (is_pubkeyalgo_initialized(metadata)) {
    unset_pubkeyalgo(metadata);
  }

  if (is_encoding_initialized(metadata)) {
    unset_encoding(metadata);
  }

  if (is_enckeyname_initialized(metadata)) {
    unset_enckeyname(metadata);
  }

  if (is_encalgo_initialized(metadata)) {
    unset_encalgo(metadata);
  }

  if (is_ivnonce_initialized(metadata)) {
    unset_ivnonce(metadata);
  }

  if (is_skeenckeyname_initialized(metadata)) {
    unset_skeenckeyname(metadata);
  }

  if (is_skeencalgo_initialized(metadata)) {
    unset_skeencalgo(metadata);
  }

  memset(metadata, 0, sizeof(atclient_atkey_metadata));
}

static bool is_createdby_initialized(const atclient_atkey_metadata *metadata) {
  return (metadata->_initializedfields[ATKEY_METADATA_CREATEDBY_INDEX] & ATKEY_METADATA_CREATEDBY_INITIALIZED);
}

static bool is_updatedby_initialized(const atclient_atkey_metadata *metadata) {
  return (metadata->_initializedfields[ATKEY_METADATA_UPDATEDBY_INDEX] & ATKEY_METADATA_UPDATEDBY_INITIALIZED);
}

static bool is_status_initialized(const atclient_atkey_metadata *metadata) {
  return (metadata->_initializedfields[ATKEY_METADATA_STATUS_INDEX] & ATKEY_METADATA_STATUS_INITIALIZED);
}

static bool is_version_initialized(const atclient_atkey_metadata *metadata) {
  return (metadata->_initializedfields[ATKEY_METADATA_VERSION_INDEX] & ATKEY_METADATA_VERSION_INITIALIZED);
}

static bool is_expiresat_initialized(const atclient_atkey_metadata *metadata) {
  return (metadata->_initializedfields[ATKEY_METADATA_EXPIRESAT_INDEX] & ATKEY_METADATA_EXPIRESAT_INITIALIZED);
}

static bool is_availableat_initialized(const atclient_atkey_metadata *metadata) {
  return (metadata->_initializedfields[ATKEY_METADATA_AVAILABLEAT_INDEX] & ATKEY_METADATA_AVAILABLEAT_INITIALIZED);
}

static bool is_refreshat_initialized(const atclient_atkey_metadata *metadata) {
  return (metadata->_initializedfields[ATKEY_METADATA_REFRESHAT_INDEX] & ATKEY_METADATA_REFRESHAT_INITIALIZED);
}

static bool is_createdat_initialized(const atclient_atkey_metadata *metadata) {
  return (metadata->_initializedfields[ATKEY_METADATA_CREATEDAT_INDEX] & ATKEY_METADATA_CREATEDAT_INITIALIZED);
}

static bool is_updatedat_initialized(const atclient_atkey_metadata *metadata) {
  return (metadata->_initializedfields[ATKEY_METADATA_UPDATEDAT_INDEX] & ATKEY_METADATA_UPDATEDAT_INITIALIZED);
}

static bool is_ispublic_initialized(const atclient_atkey_metadata *metadata) {
  return (metadata->_initializedfields[ATKEY_METADATA_ISPUBLIC_INDEX] & ATKEY_METADATA_ISPUBLIC_INITIALIZED);
}

static bool is_iscached_initialized(const atclient_atkey_metadata *metadata) {
  return (metadata->_initializedfields[ATKEY_METADATA_ISCACHED_INDEX] & ATKEY_METADATA_ISCACHED_INITIALIZED);
}

static bool is_ttl_initialized(const atclient_atkey_metadata *metadata) {
  return (metadata->_initializedfields[ATKEY_METADATA_TTL_INDEX] & ATKEY_METADATA_TTL_INITIALIZED);
}

static bool is_ttb_initialized(const atclient_atkey_metadata *metadata) {
  return (metadata->_initializedfields[ATKEY_METADATA_TTB_INDEX] & ATKEY_METADATA_TTB_INITIALIZED);
}

static bool is_ttr_initialized(const atclient_atkey_metadata *metadata) {
  return (metadata->_initializedfields[ATKEY_METADATA_TTR_INDEX] & ATKEY_METADATA_TTR_INITIALIZED);
}

static bool is_ccd_initialized(const atclient_atkey_metadata *metadata) {
  return (metadata->_initializedfields[ATKEY_METADATA_CCD_INDEX] & ATKEY_METADATA_CCD_INITIALIZED);
}

static bool is_isbinary_initialized(const atclient_atkey_metadata *metadata) {
  return (metadata->_initializedfields[ATKEY_METADATA_ISBINARY_INDEX] & ATKEY_METADATA_ISBINARY_INITIALIZED);
}

static bool is_isencrypted_initialized(const atclient_atkey_metadata *metadata) {
  return (metadata->_initializedfields[ATKEY_METADATA_ISENCRYPTED_INDEX] & ATKEY_METADATA_ISENCRYPTED_INITIALIZED);
}

static bool is_datasignature_initialized(const atclient_atkey_metadata *metadata) {
  return (metadata->_initializedfields[ATKEY_METADATA_DATASIGNATURE_INDEX] & ATKEY_METADATA_DATASIGNATURE_INITIALIZED);
}

static bool is_sharedkeystatus_initialized(const atclient_atkey_metadata *metadata) {
  return (metadata->_initializedfields[ATKEY_METADATA_SHAREDKEYSTATUS_INDEX] &
          ATKEY_METADATA_SHAREDKEYSTATUS_INITIALIZED);
}

static bool is_sharedkeyenc_initialized(const atclient_atkey_metadata *metadata) {
  return (metadata->_initializedfields[ATKEY_METADATA_SHAREDKEYENC_INDEX] & ATKEY_METADATA_SHAREDKEYENC_INITIALIZED);
}

static bool is_pubkeyhash_initialized(const atclient_atkey_metadata *metadata) {
  return (metadata->_initializedfields[ATKEY_METADATA_PUBKEYHASH_INDEX] & ATKEY_METADATA_PUBKEYHASH_INITIALIZED);
}

static bool is_pubkeyalgo_initialized(const atclient_atkey_metadata *metadata) {
  return (metadata->_initializedfields[ATKEY_METADATA_PUBKEYALGO_INDEX] & ATKEY_METADATA_PUBKEYALGO_INITIALIZED);
}

static bool is_encoding_initialized(const atclient_atkey_metadata *metadata) {
  return (metadata->_initializedfields[ATKEY_METADATA_ENCODING_INDEX] & ATKEY_METADATA_ENCODING_INITIALIZED);
}

static bool is_enckeyname_initialized(const atclient_atkey_metadata *metadata) {
  return (metadata->_initializedfields[ATKEY_METADATA_ENCKEYNAME_INDEX] & ATKEY_METADATA_ENCKEYNAME_INITIALIZED);
}

static bool is_encalgo_initialized(const atclient_atkey_metadata *metadata) {
  return (metadata->_initializedfields[ATKEY_METADATA_ENCALGO_INDEX] & ATKEY_METADATA_ENCALGO_INITIALIZED);
}

static bool is_ivnonce_initialized(const atclient_atkey_metadata *metadata) {
  return (metadata->_initializedfields[ATKEY_METADATA_IVNONCE_INDEX] & ATKEY_METADATA_IVNONCE_INITIALIZED);
}

static bool is_skeenckeyname_initialized(const atclient_atkey_metadata *metadata) {
  return (metadata->_initializedfields[ATKEY_METADATA_SKEENCKEYNAME_INDEX] & ATKEY_METADATA_SKEENCKEYNAME_INITIALIZED);
}

static bool is_skeencalgo_initialized(const atclient_atkey_metadata *metadata) {
  return (metadata->_initializedfields[ATKEY_METADATA_SKEENCALGO_INDEX] & ATKEY_METADATA_SKEENCALGO_INITIALIZED);
}

static void set_is_createdby_initialized(atclient_atkey_metadata *metadata, bool is_initialized) {
  if (is_initialized) {
    metadata->_initializedfields[ATKEY_METADATA_CREATEDBY_INDEX] |= ATKEY_METADATA_CREATEDBY_INITIALIZED;
  } else {
    metadata->_initializedfields[ATKEY_METADATA_CREATEDBY_INDEX] &= ~ATKEY_METADATA_CREATEDBY_INITIALIZED;
  }
}

static void set_is_updatedby_initialized(atclient_atkey_metadata *metadata, bool is_initialized) {
  if (is_initialized) {
    metadata->_initializedfields[ATKEY_METADATA_UPDATEDBY_INDEX] |= ATKEY_METADATA_UPDATEDBY_INITIALIZED;
  } else {
    metadata->_initializedfields[ATKEY_METADATA_UPDATEDBY_INDEX] &= ~ATKEY_METADATA_UPDATEDBY_INITIALIZED;
  }
}

static void set_is_status_initialized(atclient_atkey_metadata *metadata, bool is_initialized) {
  if (is_initialized) {
    metadata->_initializedfields[ATKEY_METADATA_STATUS_INDEX] |= ATKEY_METADATA_STATUS_INITIALIZED;
  } else {
    metadata->_initializedfields[ATKEY_METADATA_STATUS_INDEX] &= ~ATKEY_METADATA_STATUS_INITIALIZED;
  }
}

static void set_is_version_initialized(atclient_atkey_metadata *metadata, bool is_initialized) {
  if (is_initialized) {
    metadata->_initializedfields[ATKEY_METADATA_VERSION_INDEX] |= ATKEY_METADATA_VERSION_INITIALIZED;
  } else {
    metadata->_initializedfields[ATKEY_METADATA_VERSION_INDEX] &= ~ATKEY_METADATA_VERSION_INITIALIZED;
  }
}

static void set_is_expiresat_initialized(atclient_atkey_metadata *metadata, bool is_initialized) {
  if (is_initialized) {
    metadata->_initializedfields[ATKEY_METADATA_EXPIRESAT_INDEX] |= ATKEY_METADATA_EXPIRESAT_INITIALIZED;
  } else {
    metadata->_initializedfields[ATKEY_METADATA_EXPIRESAT_INDEX] &= ~ATKEY_METADATA_EXPIRESAT_INITIALIZED;
  }
}

static void set_is_availableat_initialized(atclient_atkey_metadata *metadata, bool is_initialized) {
  if (is_initialized) {
    metadata->_initializedfields[ATKEY_METADATA_AVAILABLEAT_INDEX] |= ATKEY_METADATA_AVAILABLEAT_INITIALIZED;
  } else {
    metadata->_initializedfields[ATKEY_METADATA_AVAILABLEAT_INDEX] &= ~ATKEY_METADATA_AVAILABLEAT_INITIALIZED;
  }
}

static void set_is_refreshat_initialized(atclient_atkey_metadata *metadata, bool is_initialized) {
  if (is_initialized) {
    metadata->_initializedfields[ATKEY_METADATA_REFRESHAT_INDEX] |= ATKEY_METADATA_REFRESHAT_INITIALIZED;
  } else {
    metadata->_initializedfields[ATKEY_METADATA_REFRESHAT_INDEX] &= ~ATKEY_METADATA_REFRESHAT_INITIALIZED;
  }
}

static void set_is_createdat_initialized(atclient_atkey_metadata *metadata, bool is_initialized) {
  if (is_initialized) {
    metadata->_initializedfields[ATKEY_METADATA_CREATEDAT_INDEX] |= ATKEY_METADATA_CREATEDAT_INITIALIZED;
  } else {
    metadata->_initializedfields[ATKEY_METADATA_CREATEDAT_INDEX] &= ~ATKEY_METADATA_CREATEDAT_INITIALIZED;
  }
}

static void set_is_updatedat_initialized(atclient_atkey_metadata *metadata, bool is_initialized) {
  if (is_initialized) {
    metadata->_initializedfields[ATKEY_METADATA_UPDATEDAT_INDEX] |= ATKEY_METADATA_UPDATEDAT_INITIALIZED;
  } else {
    metadata->_initializedfields[ATKEY_METADATA_UPDATEDAT_INDEX] &= ~ATKEY_METADATA_UPDATEDAT_INITIALIZED;
  }
}

static void set_is_ispublic_initialized(atclient_atkey_metadata *metadata, bool is_initialized) {
  if (is_initialized) {
    metadata->_initializedfields[ATKEY_METADATA_ISPUBLIC_INDEX] |= ATKEY_METADATA_ISPUBLIC_INITIALIZED;
  } else {
    metadata->_initializedfields[ATKEY_METADATA_ISPUBLIC_INDEX] &= ~ATKEY_METADATA_ISPUBLIC_INITIALIZED;
  }
}

static void set_is_iscached_initialized(atclient_atkey_metadata *metadata, bool is_initialized) {
  if (is_initialized) {
    metadata->_initializedfields[ATKEY_METADATA_ISCACHED_INDEX] |= ATKEY_METADATA_ISCACHED_INITIALIZED;
  } else {
    metadata->_initializedfields[ATKEY_METADATA_ISCACHED_INDEX] &= ~ATKEY_METADATA_ISCACHED_INITIALIZED;
  }
}

static void set_is_ttl_initialized(atclient_atkey_metadata *metadata, bool is_initialized) {
  if (is_initialized) {
    metadata->_initializedfields[ATKEY_METADATA_TTL_INDEX] |= ATKEY_METADATA_TTL_INITIALIZED;
  } else {
    metadata->_initializedfields[ATKEY_METADATA_TTL_INDEX] &= ~ATKEY_METADATA_TTL_INITIALIZED;
  }
}

static void set_is_ttb_initialized(atclient_atkey_metadata *metadata, bool is_initialized) {
  if (is_initialized) {
    metadata->_initializedfields[ATKEY_METADATA_TTB_INDEX] |= ATKEY_METADATA_TTB_INITIALIZED;
  } else {
    metadata->_initializedfields[ATKEY_METADATA_TTB_INDEX] &= ~ATKEY_METADATA_TTB_INITIALIZED;
  }
}

static void set_is_ttr_initialized(atclient_atkey_metadata *metadata, bool is_initialized) {
  if (is_initialized) {
    metadata->_initializedfields[ATKEY_METADATA_TTR_INDEX] |= ATKEY_METADATA_TTR_INITIALIZED;
  } else {
    metadata->_initializedfields[ATKEY_METADATA_TTR_INDEX] &= ~ATKEY_METADATA_TTR_INITIALIZED;
  }
}

static void set_is_ccd_initialized(atclient_atkey_metadata *metadata, bool is_initialized) {
  if (is_initialized) {
    metadata->_initializedfields[ATKEY_METADATA_CCD_INDEX] |= ATKEY_METADATA_CCD_INITIALIZED;
  } else {
    metadata->_initializedfields[ATKEY_METADATA_CCD_INDEX] &= ~ATKEY_METADATA_CCD_INITIALIZED;
  }
}

static void set_is_isbinary_initialized(atclient_atkey_metadata *metadata, bool is_initialized) {
  if (is_initialized) {
    metadata->_initializedfields[ATKEY_METADATA_ISBINARY_INDEX] |= ATKEY_METADATA_ISBINARY_INITIALIZED;
  } else {
    metadata->_initializedfields[ATKEY_METADATA_ISBINARY_INDEX] &= ~ATKEY_METADATA_ISBINARY_INITIALIZED;
  }
}

static void set_is_isencrypted_initialized(atclient_atkey_metadata *metadata, bool is_initialized) {
  if (is_initialized) {
    metadata->_initializedfields[ATKEY_METADATA_ISENCRYPTED_INDEX] |= ATKEY_METADATA_ISENCRYPTED_INITIALIZED;
  } else {
    metadata->_initializedfields[ATKEY_METADATA_ISENCRYPTED_INDEX] &= ~ATKEY_METADATA_ISENCRYPTED_INITIALIZED;
  }
}

static void set_is_datasignature_initialized(atclient_atkey_metadata *metadata, bool is_initialized) {
  if (is_initialized) {
    metadata->_initializedfields[ATKEY_METADATA_DATASIGNATURE_INDEX] |= ATKEY_METADATA_DATASIGNATURE_INITIALIZED;
  } else {
    metadata->_initializedfields[ATKEY_METADATA_DATASIGNATURE_INDEX] &= ~ATKEY_METADATA_DATASIGNATURE_INITIALIZED;
  }
}

static void set_is_sharedkeystatus_initialized(atclient_atkey_metadata *metadata, bool is_initialized) {
  if (is_initialized) {
    metadata->_initializedfields[ATKEY_METADATA_SHAREDKEYSTATUS_INDEX] |= ATKEY_METADATA_SHAREDKEYSTATUS_INITIALIZED;
  } else {
    metadata->_initializedfields[ATKEY_METADATA_SHAREDKEYSTATUS_INDEX] &= ~ATKEY_METADATA_SHAREDKEYSTATUS_INITIALIZED;
  }
}

static void set_is_sharedkeyenc_initialized(atclient_atkey_metadata *metadata, bool is_initialized) {
  if (is_initialized) {
    metadata->_initializedfields[ATKEY_METADATA_SHAREDKEYENC_INDEX] |= ATKEY_METADATA_SHAREDKEYENC_INITIALIZED;
  } else {
    metadata->_initializedfields[ATKEY_METADATA_SHAREDKEYENC_INDEX] &= ~ATKEY_METADATA_SHAREDKEYENC_INITIALIZED;
  }
}

static void set_is_pubkeyhash_initialized(atclient_atkey_metadata *metadata, bool is_initialized) {
  if (is_initialized) {
    metadata->_initializedfields[ATKEY_METADATA_PUBKEYHASH_INDEX] |= ATKEY_METADATA_PUBKEYHASH_INITIALIZED;
  } else {
    metadata->_initializedfields[ATKEY_METADATA_PUBKEYHASH_INDEX] &= ~ATKEY_METADATA_PUBKEYHASH_INITIALIZED;
  }
}

static void set_is_pubkeyalgo_initialized(atclient_atkey_metadata *metadata, bool is_initialized) {
  if (is_initialized) {
    metadata->_initializedfields[ATKEY_METADATA_PUBKEYALGO_INDEX] |= ATKEY_METADATA_PUBKEYALGO_INITIALIZED;
  } else {
    metadata->_initializedfields[ATKEY_METADATA_PUBKEYALGO_INDEX] &= ~ATKEY_METADATA_PUBKEYALGO_INITIALIZED;
  }
}

static void set_is_encoding_initialized(atclient_atkey_metadata *metadata, bool is_initialized) {
  if (is_initialized) {
    metadata->_initializedfields[ATKEY_METADATA_ENCODING_INDEX] |= ATKEY_METADATA_ENCODING_INITIALIZED;
  } else {
    metadata->_initializedfields[ATKEY_METADATA_ENCODING_INDEX] &= ~ATKEY_METADATA_ENCODING_INITIALIZED;
  }
}

static void set_is_enckeyname_initialized(atclient_atkey_metadata *metadata, bool is_initialized) {
  if (is_initialized) {
    metadata->_initializedfields[ATKEY_METADATA_ENCKEYNAME_INDEX] |= ATKEY_METADATA_ENCKEYNAME_INITIALIZED;
  } else {
    metadata->_initializedfields[ATKEY_METADATA_ENCKEYNAME_INDEX] &= ~ATKEY_METADATA_ENCKEYNAME_INITIALIZED;
  }
}

static void set_is_encalgo_initialized(atclient_atkey_metadata *metadata, bool is_initialized) {
  if (is_initialized) {
    metadata->_initializedfields[ATKEY_METADATA_ENCALGO_INDEX] |= ATKEY_METADATA_ENCALGO_INITIALIZED;
  } else {
    metadata->_initializedfields[ATKEY_METADATA_ENCALGO_INDEX] &= ~ATKEY_METADATA_ENCALGO_INITIALIZED;
  }
}

static void set_is_ivnonce_initialized(atclient_atkey_metadata *metadata, bool is_initialized) {
  if (is_initialized) {
    metadata->_initializedfields[ATKEY_METADATA_IVNONCE_INDEX] |= ATKEY_METADATA_IVNONCE_INITIALIZED;
  } else {
    metadata->_initializedfields[ATKEY_METADATA_IVNONCE_INDEX] &= ~ATKEY_METADATA_IVNONCE_INITIALIZED;
  }
}

static void set_is_skeenckeyname_initialized(atclient_atkey_metadata *metadata, bool is_initialized) {
  if (is_initialized) {
    metadata->_initializedfields[ATKEY_METADATA_SKEENCKEYNAME_INDEX] |= ATKEY_METADATA_SKEENCKEYNAME_INITIALIZED;
  } else {
    metadata->_initializedfields[ATKEY_METADATA_SKEENCKEYNAME_INDEX] &= ~ATKEY_METADATA_SKEENCKEYNAME_INITIALIZED;
  }
}

static void set_is_skeencalgo_initialized(atclient_atkey_metadata *metadata, bool is_initialized) {
  if (is_initialized) {
    metadata->_initializedfields[ATKEY_METADATA_SKEENCALGO_INDEX] |= ATKEY_METADATA_SKEENCALGO_INITIALIZED;
  } else {
    metadata->_initializedfields[ATKEY_METADATA_SKEENCALGO_INDEX] &= ~ATKEY_METADATA_SKEENCALGO_INITIALIZED;
  }
}

static void unset_createdby(atclient_atkey_metadata *metadata) {
  if (is_createdby_initialized(metadata)) {
    free(metadata->createdby);
  }
  metadata->createdby = NULL;
  set_is_createdby_initialized(metadata, false);
}

static void unset_updatedby(atclient_atkey_metadata *metadata) {
  if (is_updatedby_initialized(metadata)) {
    free(metadata->updatedby);
  }
  metadata->updatedby = NULL;
  set_is_updatedby_initialized(metadata, false);
}

static void unset_status(atclient_atkey_metadata *metadata) {
  if (is_status_initialized(metadata)) {
    free(metadata->status);
  }
  metadata->status = NULL;
  set_is_status_initialized(metadata, false);
}

static void unset_version(atclient_atkey_metadata *metadata) {
  metadata->version = 0;
  set_is_version_initialized(metadata, false);
}

static void unset_expiresat(atclient_atkey_metadata *metadata) {
  if (is_expiresat_initialized(metadata)) {
    free(metadata->expiresat);
  }
  metadata->expiresat = NULL;
  set_is_expiresat_initialized(metadata, false);
}

static void unset_availableat(atclient_atkey_metadata *metadata) {
  if (is_availableat_initialized(metadata)) {
    free(metadata->availableat);
  }
  metadata->availableat = NULL;
  set_is_availableat_initialized(metadata, false);
}

static void unset_refreshat(atclient_atkey_metadata *metadata) {
  if (is_refreshat_initialized(metadata)) {
    free(metadata->refreshat);
  }
  metadata->refreshat = NULL;
  set_is_refreshat_initialized(metadata, false);
}

static void unset_createdat(atclient_atkey_metadata *metadata) {
  if (is_createdat_initialized(metadata)) {
    free(metadata->createdat);
  }
  metadata->createdat = NULL;
  set_is_createdat_initialized(metadata, false);
}

static void unset_updatedat(atclient_atkey_metadata *metadata) {
  if (is_updatedat_initialized(metadata)) {
    free(metadata->updatedat);
  }
  metadata->updatedat = NULL;
  set_is_updatedat_initialized(metadata, false);
}

static void unset_ispublic(atclient_atkey_metadata *metadata) {
  metadata->ispublic = false;
  set_is_ispublic_initialized(metadata, false);
}

static void unset_iscached(atclient_atkey_metadata *metadata) {
  metadata->iscached = false;
  set_is_iscached_initialized(metadata, false);
}

static void unset_ttl(atclient_atkey_metadata *metadata) {
  metadata->ttl = 0;
  set_is_ttl_initialized(metadata, false);
}

static void unset_ttb(atclient_atkey_metadata *metadata) {
  metadata->ttb = 0;
  set_is_ttb_initialized(metadata, false);
}

static void unset_ttr(atclient_atkey_metadata *metadata) {
  metadata->ttr = 0;
  set_is_ttr_initialized(metadata, false);
}

static void unset_ccd(atclient_atkey_metadata *metadata) {
  metadata->ccd = false;
  set_is_ccd_initialized(metadata, false);
}

static void unset_isbinary(atclient_atkey_metadata *metadata) {
  metadata->isbinary = false;
  set_is_isbinary_initialized(metadata, false);
}

static void unset_isencrypted(atclient_atkey_metadata *metadata) {
  metadata->isencrypted = false;
  set_is_isencrypted_initialized(metadata, false);
}

static void unset_datasignature(atclient_atkey_metadata *metadata) {
  if (is_datasignature_initialized(metadata)) {
    free(metadata->datasignature);
  }
  metadata->datasignature = NULL;
  set_is_datasignature_initialized(metadata, false);
}

static void unset_sharedkeystatus(atclient_atkey_metadata *metadata) {
  if (is_sharedkeystatus_initialized(metadata)) {
    free(metadata->sharedkeystatus);
  }
  metadata->sharedkeystatus = NULL;
  set_is_sharedkeystatus_initialized(metadata, false);
}

static void unset_sharedkeyenc(atclient_atkey_metadata *metadata) {
  if (is_sharedkeyenc_initialized(metadata)) {
    free(metadata->sharedkeyenc);
  }
  metadata->sharedkeyenc = NULL;
  set_is_sharedkeyenc_initialized(metadata, false);
}

static void unset_pubkeyhash(atclient_atkey_metadata *metadata) {
  if (is_pubkeyhash_initialized(metadata)) {
    free(metadata->pubkeyhash);
  }
  metadata->pubkeyhash = NULL;
  set_is_pubkeyhash_initialized(metadata, false);
}

static void unset_pubkeyalgo(atclient_atkey_metadata *metadata) {
  if (is_pubkeyalgo_initialized(metadata)) {
    free(metadata->pubkeyalgo);
  }
  metadata->pubkeyalgo = NULL;
  set_is_pubkeyalgo_initialized(metadata, false);
}

static void unset_encoding(atclient_atkey_metadata *metadata) {
  if (is_encoding_initialized(metadata)) {
    free(metadata->encoding);
  }
  metadata->encoding = NULL;
  set_is_encoding_initialized(metadata, false);
}

static void unset_enckeyname(atclient_atkey_metadata *metadata) {
  if (is_enckeyname_initialized(metadata)) {
    free(metadata->enckeyname);
  }
  set_is_enckeyname_initialized(metadata, false);
}

static void unset_encalgo(atclient_atkey_metadata *metadata) {
  if (is_encalgo_initialized(metadata)) {
    free(metadata->encalgo);
  }
  metadata->encalgo = NULL;
  set_is_encalgo_initialized(metadata, false);
}

static void unset_ivnonce(atclient_atkey_metadata *metadata) {
  if (is_ivnonce_initialized(metadata)) {
    free(metadata->ivnonce);
  }
  metadata->ivnonce = NULL;
  set_is_ivnonce_initialized(metadata, false);
}

static void unset_skeenckeyname(atclient_atkey_metadata *metadata) {
  if (is_skeenckeyname_initialized(metadata)) {
    free(metadata->skeenckeyname);
  }
  metadata->skeenckeyname = NULL;
  set_is_skeenckeyname_initialized(metadata, false);
}

static void unset_skeencalgo(atclient_atkey_metadata *metadata) {
  if (is_skeencalgo_initialized(metadata)) {
    free(metadata->skeencalgo);
  }
  metadata->skeencalgo = NULL;
  set_is_skeencalgo_initialized(metadata, false);
}

static int set_createdby(atclient_atkey_metadata *metadata, const char *createdby) {
  int ret = 1;
  const size_t createdbylen = strlen(createdby);
  const size_t createdbysize = createdbylen + 1;
  if ((metadata->createdby = malloc(sizeof(char) * (createdbysize))) == NULL) {
    ret = 1;
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "set_createdby malloc failed\n");
    goto exit;
  }
  memcpy(metadata->createdby, createdby, createdbylen);
  metadata->createdby[createdbylen] = '\0';
  set_is_createdby_initialized(metadata, true);
  ret = 0;
  goto exit;
exit: { return ret; }
}

static int set_updatedby(atclient_atkey_metadata *metadata, const char *updatedby) {
  int ret = 1;
  const size_t updatedbylen = strlen(updatedby);
  const size_t updatedbysize = updatedbylen + 1;
  if ((metadata->updatedby = malloc(sizeof(char) * (updatedbysize))) == NULL) {
    ret = 1;
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "set_updatedby malloc failed\n");
    goto exit;
  }
  memcpy(metadata->updatedby, updatedby, updatedbylen);
  metadata->updatedby[updatedbylen] = '\0';
  set_is_updatedby_initialized(metadata, true);
  ret = 0;
  goto exit;
exit: { return ret; }
}

static int set_status(atclient_atkey_metadata *metadata, const char *status) {
  int ret = 1;
  const size_t statuslen = strlen(status);
  const size_t statussize = statuslen + 1;
  if ((metadata->status = malloc(sizeof(char) * (statussize))) == NULL) {
    ret = 1;
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "set_status malloc failed\n");
    goto exit;
  }
  memcpy(metadata->status, status, statuslen);
  metadata->status[statuslen] = '\0';
  set_is_status_initialized(metadata, true);
  ret = 0;
  goto exit;
exit: { return ret; }
}

static void set_version(atclient_atkey_metadata *metadata, int version) {
  metadata->version = version;
  set_is_version_initialized(metadata, true);
}

static int set_expiresat(atclient_atkey_metadata *metadata, const char *expiresat) {
  int ret = 1;
  const size_t expiresatlen = strlen(expiresat);
  const size_t expiresatsize = expiresatlen + 1;
  if ((metadata->expiresat = malloc(sizeof(char) * (expiresatsize))) == NULL) {
    ret = 1;
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "set_expiresat malloc failed\n");
    goto exit;
  }
  memcpy(metadata->expiresat, expiresat, expiresatlen);
  metadata->expiresat[expiresatlen] = '\0';
  set_is_expiresat_initialized(metadata, true);
  ret = 0;
  goto exit;
exit: { return ret; }
}

static int set_availableat(atclient_atkey_metadata *metadata, const char *availableat) {
  int ret = 1;
  const size_t availableatlen = strlen(availableat);
  const size_t availableatsize = availableatlen + 1;
  if ((metadata->availableat = malloc(sizeof(char) * (availableatsize))) == NULL) {
    ret = 1;
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "set_availableat malloc failed\n");
    goto exit;
  }
  memcpy(metadata->availableat, availableat, availableatlen);
  metadata->availableat[availableatlen] = '\0';
  set_is_availableat_initialized(metadata, true);
  ret = 0;
  goto exit;
exit: { return ret; }
}

static int set_refreshat(atclient_atkey_metadata *metadata, const char *refreshat) {
  int ret = 1;
  const size_t refreshatlen = strlen(refreshat);
  const size_t refreshatsize = refreshatlen + 1;
  if ((metadata->refreshat = malloc(sizeof(char) * (refreshatsize))) == NULL) {
    ret = 1;
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "set_refreshat malloc failed\n");
    goto exit;
  }
  memcpy(metadata->refreshat, refreshat, refreshatlen);
  metadata->refreshat[refreshatlen] = '\0';
  set_is_refreshat_initialized(metadata, true);
  ret = 0;
  goto exit;
exit: { return ret; }
}

static int set_createdat(atclient_atkey_metadata *metadata, const char *createdat) {
  int ret = 1;
  const size_t createdatlen = strlen(createdat);
  const size_t createdatsize = createdatlen + 1;
  if ((metadata->createdat = malloc(sizeof(char) * (createdatlen + 1))) == NULL) {
    ret = 1;
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "set_createdat malloc failed\n");
    goto exit;
  }
  memcpy(metadata->createdat, createdat, createdatlen);
  metadata->createdat[createdatlen] = '\0';
  set_is_createdat_initialized(metadata, true);
  ret = 0;
  goto exit;
exit: { return ret; }
}

static int set_updatedat(atclient_atkey_metadata *metadata, const char *updatedat) {
  int ret = 1;
  const size_t updatedatlen = strlen(updatedat);
  const size_t updatedatsize = updatedatlen + 1;
  if ((metadata->updatedat = malloc(sizeof(char) * (updatedatsize))) == NULL) {
    ret = 1;
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "set_updatedat malloc failed\n");
    goto exit;
  }
  memcpy(metadata->updatedat, updatedat, updatedatlen);
  metadata->updatedat[updatedatlen] = '\0';
  set_is_updatedat_initialized(metadata, true);
  ret = 0;
  goto exit;
exit: { return ret; }
}

static void set_ispublic(atclient_atkey_metadata *metadata, const bool ispublic) {
  metadata->ispublic = ispublic;
  set_is_ispublic_initialized(metadata, true);
}

static void set_iscached(atclient_atkey_metadata *metadata, const bool iscached) {
  metadata->iscached = iscached;
  set_is_iscached_initialized(metadata, true);
}

static void set_ttl(atclient_atkey_metadata *metadata, const long ttl) {
  metadata->ttl = ttl;
  set_is_ttl_initialized(metadata, true);
}

static void set_ttb(atclient_atkey_metadata *metadata, const long ttb) {
  metadata->ttb = ttb;
  set_is_ttb_initialized(metadata, true);
}

static void set_ttr(atclient_atkey_metadata *metadata, const long ttr) {
  metadata->ttr = ttr;
  set_is_ttr_initialized(metadata, true);
}

static void set_ccd(atclient_atkey_metadata *metadata, const bool ccd) {
  metadata->ccd = ccd;
  set_is_ccd_initialized(metadata, true);
}

static void set_isbinary(atclient_atkey_metadata *metadata, const bool isbinary) {
  metadata->isbinary = isbinary;
  set_is_isbinary_initialized(metadata, true);
}

static void set_isencrypted(atclient_atkey_metadata *metadata, const bool isencrypted) {
  metadata->isencrypted = isencrypted;
  set_is_isencrypted_initialized(metadata, true);
}

static int set_datasignature(atclient_atkey_metadata *metadata, const char *datasignature) {
  int ret = 1;
  const size_t datasignaturelen = strlen(datasignature);
  const size_t datasignaturesize = datasignaturelen + 1;
  if ((metadata->datasignature = malloc(sizeof(char) * (datasignaturesize))) == NULL) {
    ret = 1;
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "set_datasignature malloc failed\n");
    goto exit;
  }
  memcpy(metadata->datasignature, datasignature, datasignaturelen);
  metadata->datasignature[datasignaturelen] = '\0';
  set_is_datasignature_initialized(metadata, true);
  ret = 0;
  goto exit;
exit: { return ret; }
}

static int set_sharedkeystatus(atclient_atkey_metadata *metadata, const char *sharedkeystatus) {
  int ret = 1;
  const size_t sharedkeystatuslen = strlen(sharedkeystatus);
  const size_t sharedkeystatussize = sharedkeystatuslen + 1;
  if ((metadata->sharedkeystatus = malloc(sizeof(char) * (sharedkeystatussize))) == NULL) {
    ret = 1;
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "set_sharedkeystatus malloc failed\n");
    goto exit;
  }
  memcpy(metadata->sharedkeystatus, sharedkeystatus, sharedkeystatuslen);
  metadata->sharedkeystatus[sharedkeystatuslen] = '\0';
  set_is_sharedkeystatus_initialized(metadata, true);
  ret = 0;
  goto exit;
exit: { return ret; }
}

static int set_sharedkeyenc(atclient_atkey_metadata *metadata, const char *sharedkeyenc) {
  int ret = 1;
  const size_t sharedkeyenclen = strlen(sharedkeyenc);
  const size_t sharedkeyencsize = sharedkeyenclen + 1;
  if ((metadata->sharedkeyenc = malloc(sizeof(char) * (sharedkeyencsize))) == NULL) {
    ret = 1;
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "set_sharedkeyenc malloc failed\n");
    goto exit;
  }
  memcpy(metadata->sharedkeyenc, sharedkeyenc, sharedkeyenclen);
  metadata->sharedkeyenc[sharedkeyenclen] = '\0';
  set_is_sharedkeyenc_initialized(metadata, true);
  ret = 0;
  goto exit;
exit: { return ret; }
}

static int set_pubkeyhash(atclient_atkey_metadata *metadata, const char *pubkeyhash) {
  int ret = 1;
  const size_t pubkeyhashlen = strlen(pubkeyhash);
  const size_t pubkeyhashsize = pubkeyhashlen + 1;
  if ((metadata->pubkeyhash = malloc(sizeof(char) * (pubkeyhashsize))) == NULL) {
    ret = 1;
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "set_pubkeyhash malloc failed\n");
    goto exit;
  }
  memcpy(metadata->pubkeyhash, pubkeyhash, pubkeyhashlen);
  metadata->pubkeyhash[pubkeyhashlen] = '\0';
  set_is_pubkeyhash_initialized(metadata, true);
  ret = 0;
  goto exit;
exit: { return ret; }
}

static int set_pubkeyalgo(atclient_atkey_metadata *metadata, const char *pubkeyalgo) {
  int ret = 1;
  const size_t pubkeyalgolen = strlen(pubkeyalgo);
  const size_t pubkeyalgosize = pubkeyalgolen + 1;
  if ((metadata->pubkeyalgo = malloc(sizeof(char) * (pubkeyalgosize))) == NULL) {
    ret = 1;
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "set_pubkeyalgo malloc failed\n");
    goto exit;
  }
  memcpy(metadata->pubkeyalgo, pubkeyalgo, pubkeyalgolen);
  metadata->pubkeyalgo[pubkeyalgolen] = '\0';
  set_is_pubkeyalgo_initialized(metadata, true);
  ret = 0;
  goto exit;
exit: { return ret; }
}

static int set_encoding(atclient_atkey_metadata *metadata, const char *encoding) {
  int ret = 1;
  const size_t encodinglen = strlen(encoding);
  const size_t encodingsize = encodinglen + 1;
  if ((metadata->encoding = malloc(sizeof(char) * (encodingsize))) == NULL) {
    ret = 1;
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "set_encoding malloc failed\n");
    goto exit;
  }
  memcpy(metadata->encoding, encoding, encodinglen);
  metadata->encoding[encodinglen] = '\0';
  set_is_encoding_initialized(metadata, true);
  ret = 0;
  goto exit;
exit: { return ret; }
}

static int set_enckeyname(atclient_atkey_metadata *metadata, const char *enckeyname) {
  int ret = 1;
  const size_t enckeynamelen = strlen(enckeyname);
  const size_t enckeynamesize = enckeynamelen + 1;
  if ((metadata->enckeyname = malloc(sizeof(char) * (enckeynamesize))) == NULL) {
    ret = 1;
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "set_enckeyname malloc failed\n");
    goto exit;
  }
  memcpy(metadata->enckeyname, enckeyname, enckeynamelen);
  metadata->enckeyname[enckeynamelen] = '\0';
  set_is_enckeyname_initialized(metadata, true);
  ret = 0;
  goto exit;
exit: { return ret; }
}

static int set_encalgo(atclient_atkey_metadata *metadata, const char *encalgo) {
  int ret = 1;
  const size_t encalgolen = strlen(encalgo);
  const size_t encalgosize = encalgolen + 1;
  if ((metadata->encalgo = malloc(sizeof(char) * (encalgosize))) == NULL) {
    ret = 1;
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "set_encalgo malloc failed\n");
    goto exit;
  }
  memcpy(metadata->encalgo, encalgo, encalgolen);
  metadata->encalgo[encalgolen] = '\0';
  set_is_encalgo_initialized(metadata, true);
  ret = 0;
  goto exit;
exit: { return ret; }
}

static int set_ivnonce(atclient_atkey_metadata *metadata, const char *ivnonce) {
  int ret = 1;
  const size_t ivnoncelen = strlen(ivnonce);
  const size_t ivnoncesize = ivnoncelen + 1;
  if ((metadata->ivnonce = malloc(sizeof(char) * (ivnoncesize))) == NULL) {
    ret = 1;
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "set_ivnonce malloc failed\n");
    goto exit;
  }
  memcpy(metadata->ivnonce, ivnonce, ivnoncelen);
  metadata->ivnonce[ivnoncelen] = '\0';
  set_is_ivnonce_initialized(metadata, true);
  ret = 0;
  goto exit;
exit: { return ret; }
}

static int set_skeenckeyname(atclient_atkey_metadata *metadata, const char *skeenckeyname) {
  int ret = 1;
  const size_t skeenckeynamelen = strlen(skeenckeyname);
  const size_t skeenckeynamesize = skeenckeynamelen + 1;
  if ((metadata->skeenckeyname = malloc(sizeof(char) * (skeenckeynamesize))) == NULL) {
    ret = 1;
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "set_skeenckeyname malloc failed\n");
    goto exit;
  }
  memcpy(metadata->skeenckeyname, skeenckeyname, skeenckeynamelen);
  metadata->skeenckeyname[skeenckeynamelen] = '\0';
  set_is_skeenckeyname_initialized(metadata, true);
  ret = 0;
  goto exit;
exit: { return ret; }
}

static int set_skeencalgo(atclient_atkey_metadata *metadata, const char *skeencalgo) {
  int ret = 1;
  const size_t skeencalgolen = strlen(skeencalgo);
  const size_t skeencalgosize = skeencalgolen + 1;
  if ((metadata->skeencalgo = malloc(sizeof(char) * (skeencalgosize))) == NULL) {
    ret = 1;
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "set_skeencalgo malloc failed\n");
    goto exit;
  }
  memcpy(metadata->skeencalgo, skeencalgo, skeencalgolen);
  metadata->skeencalgo[skeencalgolen] = '\0';
  set_is_skeencalgo_initialized(metadata, true);
  ret = 0;
  goto exit;
exit: { return ret; }
}
