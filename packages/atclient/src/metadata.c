#include "atclient/metadata.h"
#include "atclient/atsign.h"
#include "atclient/atstr.h"
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
static bool is_ishidden_initialized(const atclient_atkey_metadata *metadata);
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
static void set_is_ishidden_initialized(atclient_atkey_metadata *metadata, bool is_initialized);
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
static void unset_ishidden(atclient_atkey_metadata *metadata);
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

static int set_createdby(atclient_atkey_metadata *metadata, const char *createdby, const size_t createdbylen);
static int set_updatedby(atclient_atkey_metadata *metadata, const char *updatedby, const size_t updatedbylen);
static int set_status(atclient_atkey_metadata *metadata, const char *status, const size_t statuslen);
static void set_version(atclient_atkey_metadata *metadata, int version);
static int set_expiresat(atclient_atkey_metadata *metadata, const char *expiresat, const size_t expiresatlen);
static int set_availableat(atclient_atkey_metadata *metadata, const char *availableat, const size_t availableatlen);
static int set_refreshat(atclient_atkey_metadata *metadata, const char *refreshat, const size_t refreshatlen);
static int set_createdat(atclient_atkey_metadata *metadata, const char *createdat, const size_t createdatlen);
static int set_updatedat(atclient_atkey_metadata *metadata, const char *updatedat, const size_t updatedatlen);
static void set_ispublic(atclient_atkey_metadata *metadata, const bool ispublic);
static void set_ishidden(atclient_atkey_metadata *metadata, const bool ishidden);
static void set_iscached(atclient_atkey_metadata *metadata, const bool iscached);
static void set_ttl(atclient_atkey_metadata *metadata, const long ttl);
static void set_ttb(atclient_atkey_metadata *metadata, const long ttb);
static void set_ttr(atclient_atkey_metadata *metadata, const long ttr);
static void set_ccd(atclient_atkey_metadata *metadata, const bool ccd);
static void set_isbinary(atclient_atkey_metadata *metadata, const bool isbinary);
static void set_isencrypted(atclient_atkey_metadata *metadata, const bool isencrypted);
static int set_datasignature(atclient_atkey_metadata *metadata, const char *datasignature,
                             const size_t datasignaturelen);
static int set_sharedkeystatus(atclient_atkey_metadata *metadata, const char *sharedkeystatus,
                               const size_t sharedkeystatuslen);
static int set_sharedkeyenc(atclient_atkey_metadata *metadata, const char *sharedkeyenc, const size_t sharedkeyenclen);
static int set_pubkeyhash(atclient_atkey_metadata *metadata, const char *pubkeyhash, const size_t pubkeyhashlen);
static int set_pubkeyalgo(atclient_atkey_metadata *metadata, const char *pubkeyalgo, const size_t pubkeyalgolen);
static int set_encoding(atclient_atkey_metadata *metadata, const char *encoding, const size_t encodinglen);
static int set_enckeyname(atclient_atkey_metadata *metadata, const char *enckeyname, const size_t enckeynamelen);
static int set_encalgo(atclient_atkey_metadata *metadata, const char *encalgo, const size_t encalgolen);
static int set_ivnonce(atclient_atkey_metadata *metadata, const char *ivnonce, const size_t ivnoncelen);
static int set_skeenckeyname(atclient_atkey_metadata *metadata, const char *skeenckeyname,
                             const size_t skeenckeynamelen);
static int set_skeencalgo(atclient_atkey_metadata *metadata, const char *skeencalgo, const size_t skeencalgolen);

void atclient_atkey_metadata_init(atclient_atkey_metadata *metadata) {
  memset(metadata, 0, sizeof(atclient_atkey_metadata));
}

int atclient_atkey_metadata_from_jsonstr(atclient_atkey_metadata *metadata, const char *metadatastr,
                                         const size_t metadatastrlen) {
  int ret = 1;

  cJSON *root = cJSON_Parse(metadatastr);
  if (root == NULL) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "cJSON_Parse failed\n");
    goto exit;
  }
  atclient_atkey_metadata_from_cjson_node(metadata, root);
  cJSON_Delete(root);

  ret = 0;
  goto exit;

exit: { return ret; }
}

void atclient_atkey_metadata_from_cjson_node(atclient_atkey_metadata *metadata, const cJSON *json) {
  cJSON *createdby = cJSON_GetObjectItem(json, "createdBy");
  if (createdby != NULL) {
    if (createdby->type != cJSON_NULL) {
      set_createdby(metadata, createdby->valuestring, strlen(createdby->valuestring));
    } else {
      set_createdby(metadata, "null", 4);
    }
  }

  cJSON *updatedby = cJSON_GetObjectItem(json, "updatedBy");
  if (updatedby != NULL) {
    if (updatedby->type != cJSON_NULL) {
      set_updatedby(metadata, updatedby->valuestring, strlen(updatedby->valuestring));
    } else {
      set_updatedby(metadata, "null", 4);
    }
  }

  cJSON *status = cJSON_GetObjectItem(json, "status");
  if (status != NULL) {
    if (status->type != cJSON_NULL) {
      set_status(metadata, status->valuestring, strlen(status->valuestring));
    } else {
      set_status(metadata, "null", 4);
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
      set_expiresat(metadata, expiresat->valuestring, strlen(expiresat->valuestring));
    } else {
      set_expiresat(metadata, "null", 4);
    }
  }

  cJSON *availableat = cJSON_GetObjectItem(json, "availableAt");
  if (availableat != NULL) {
    if (availableat->type != cJSON_NULL) {
      set_availableat(metadata, availableat->valuestring, strlen(availableat->valuestring));
    } else {
      set_availableat(metadata, "null", 4);
    }
  }

  cJSON *refreshat = cJSON_GetObjectItem(json, "refreshAt");
  if (refreshat != NULL) {
    if (refreshat->type != cJSON_NULL) {
      set_refreshat(metadata, refreshat->valuestring, strlen(refreshat->valuestring));
    } else {
      set_refreshat(metadata, "null", 4);
    }
  }

  cJSON *createdat = cJSON_GetObjectItem(json, "createdAt");
  if (createdat != NULL) {
    if (createdat->type != cJSON_NULL) {
      set_createdat(metadata, createdat->valuestring, strlen(createdat->valuestring));
    } else {
      set_createdat(metadata, "null", 4);
    }
  }

  cJSON *updatedat = cJSON_GetObjectItem(json, "updatedAt");
  if (updatedat != NULL) {
    if (updatedat->type != cJSON_NULL) {
      set_updatedat(metadata, updatedat->valuestring, strlen(updatedat->valuestring));
    } else {
      set_updatedat(metadata, "null", 4);
    }
  }

  // I don't think this field exists when reading metadata from atServer
  // cJSON *ispublic = cJSON_GetObjectItem(root, "isPublic");
  // if(ispublic != NULL) {
  //   set_ispublic(metadata, ispublic->valueint);
  // }

  // I don't think this field exists when reading metadata from atServer
  // cJSON *ishidden = cJSON_GetObjectItem(root, "isHidden");
  // if(ishidden != NULL) {
  //   set_ishidden(metadata, ishidden->valueint);
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
      set_datasignature(metadata, datasignature->valuestring, strlen(datasignature->valuestring));
    } else {
      set_datasignature(metadata, "null", 4);
    }
  }

  cJSON *sharedkeystatus = cJSON_GetObjectItem(json, "sharedKeyStatus");
  if (sharedkeystatus != NULL) {
    if (sharedkeystatus->type != cJSON_NULL) {
      set_sharedkeystatus(metadata, sharedkeystatus->valuestring, strlen(sharedkeystatus->valuestring));
    } else {
      set_sharedkeystatus(metadata, "null", 4);
    }
  }

  cJSON *sharedkeyenc = cJSON_GetObjectItem(json, "sharedKeyEnc");
  if (sharedkeyenc != NULL) {
    if (sharedkeyenc->type != cJSON_NULL) {
      set_sharedkeyenc(metadata, sharedkeyenc->valuestring, strlen(sharedkeyenc->valuestring));
    } else {
      set_sharedkeyenc(metadata, "null", 4);
    }
  }

  cJSON *pubkeyhash = cJSON_GetObjectItem(json, "pubKeyHash");
  if (pubkeyhash != NULL) {
    if (pubkeyhash->type != cJSON_NULL) {
      set_pubkeyhash(metadata, pubkeyhash->valuestring, strlen(pubkeyhash->valuestring));
    } else {
      set_pubkeyhash(metadata, "null", 4);
    }
  }

  cJSON *pubkeyalgo = cJSON_GetObjectItem(json, "pubKeyAlgo");
  if (pubkeyalgo != NULL) {
    if (pubkeyalgo->type != cJSON_NULL) {
      set_pubkeyalgo(metadata, pubkeyalgo->valuestring, strlen(pubkeyalgo->valuestring));
    } else {
      set_pubkeyalgo(metadata, "null", 4);
    }
  }

  cJSON *encoding = cJSON_GetObjectItem(json, "encoding");
  if (encoding != NULL) {
    if (encoding->type != cJSON_NULL) {
      set_encoding(metadata, encoding->valuestring, strlen(encoding->valuestring));
    } else {
      set_encoding(metadata, "null", 4);
    }
  }

  cJSON *enckeyname = cJSON_GetObjectItem(json, "encKeyName");
  if (enckeyname != NULL) {
    if (enckeyname->type != cJSON_NULL) {
      set_enckeyname(metadata, enckeyname->valuestring, strlen(enckeyname->valuestring));
    } else {
      set_enckeyname(metadata, "null", 4);
    }
  }

  cJSON *encalgo = cJSON_GetObjectItem(json, "encAlgo");
  if (encalgo != NULL) {
    if (encalgo->type != cJSON_NULL) {
      set_encalgo(metadata, encalgo->valuestring, strlen(encalgo->valuestring));
    } else {
      set_encalgo(metadata, "null", 4);
    }
  }

  cJSON *ivnonce = cJSON_GetObjectItem(json, "ivNonce");
  if (ivnonce != NULL) {
    if (ivnonce->type != cJSON_NULL) {
      set_ivnonce(metadata, ivnonce->valuestring, strlen(ivnonce->valuestring));
    } else {
      set_ivnonce(metadata, "null", 4);
    }
  }

  cJSON *skeenckeyname = cJSON_GetObjectItem(json, "skeEncKeyName");
  if (skeenckeyname != NULL) {
    if (skeenckeyname->type != cJSON_NULL) {
      set_skeenckeyname(metadata, skeenckeyname->valuestring, strlen(skeenckeyname->valuestring));
    } else {
      set_skeenckeyname(metadata, "null", 4);
    }
  }

  cJSON *skeencalgo = cJSON_GetObjectItem(json, "skeEncAlgo");
  if (skeencalgo != NULL) {
    if (skeencalgo->type != cJSON_NULL) {
      set_skeencalgo(metadata, skeencalgo->valuestring, strlen(skeencalgo->valuestring));
    } else {
      set_skeencalgo(metadata, "null", 4);
    }
  }
}

int atclient_atkey_metadata_to_jsonstr(const atclient_atkey_metadata *metadata, char *metadatastr,
                                       const size_t metadatastrsize, size_t *metadatastrlen) {
  int ret = 1;

  cJSON *root = cJSON_CreateObject();

  if (atclient_atkey_metadata_is_createdby_initialized(metadata)) {
    cJSON_AddStringToObject(root, "createdBy", metadata->createdby.atsign);
  }

  if (atclient_atkey_metadata_is_updatedby_initialized(metadata)) {
    cJSON_AddStringToObject(root, "updatedBy", metadata->updatedby.atsign);
  }

  if (atclient_atkey_metadata_is_status_initialized(metadata)) {
    cJSON_AddStringToObject(root, "status", metadata->status.str);
  }

  if (atclient_atkey_metadata_is_version_initialized(metadata)) {
    cJSON_AddNumberToObject(root, "version", metadata->version);
  }

  if (atclient_atkey_metadata_is_expiresat_initialized(metadata)) {
    cJSON_AddStringToObject(root, "expiresAt", metadata->expiresat.str);
  }

  if (atclient_atkey_metadata_is_availableat_initialized(metadata)) {
    cJSON_AddStringToObject(root, "availableAt", metadata->availableat.str);
  }

  if (atclient_atkey_metadata_is_refreshat_initialized(metadata)) {
    cJSON_AddStringToObject(root, "refreshAt", metadata->refreshat.str);
  }

  if (atclient_atkey_metadata_is_createdat_initialized(metadata)) {
    cJSON_AddStringToObject(root, "createdAt", metadata->createdat.str);
  }

  if (atclient_atkey_metadata_is_updatedat_initialized(metadata)) {
    cJSON_AddStringToObject(root, "updatedAt", metadata->updatedat.str);
  }

  if (atclient_atkey_metadata_is_ispublic_initialized(metadata)) {
    cJSON_AddBoolToObject(root, "isPublic", metadata->ispublic);
  }

  if (atclient_atkey_metadata_is_ishidden_initialized(metadata)) {
    cJSON_AddBoolToObject(root, "isHidden", metadata->ishidden);
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
    cJSON_AddStringToObject(root, "dataSignature", metadata->datasignature.str);
  }

  if (atclient_atkey_metadata_is_sharedkeystatus_initialized(metadata)) {
    cJSON_AddStringToObject(root, "sharedKeyStatus", metadata->sharedkeystatus.str);
  }

  if (atclient_atkey_metadata_is_sharedkeyenc_initialized(metadata)) {
    cJSON_AddStringToObject(root, "sharedKeyEnc", metadata->sharedkeyenc.str);
  }

  if (atclient_atkey_metadata_is_pubkeyhash_initialized(metadata)) {
    cJSON_AddStringToObject(root, "pubKeyHash", metadata->pubkeyhash.str);
  }

  if (atclient_atkey_metadata_is_pubkeyalgo_initialized(metadata)) {
    cJSON_AddStringToObject(root, "pubKeyAlgo", metadata->pubkeyalgo.str);
  }

  if (atclient_atkey_metadata_is_encoding_initialized(metadata)) {
    cJSON_AddStringToObject(root, "encoding", metadata->encoding.str);
  }

  if (atclient_atkey_metadata_is_enckeyname_initialized(metadata)) {
    cJSON_AddStringToObject(root, "encKeyName", metadata->enckeyname.str);
  }

  if (atclient_atkey_metadata_is_encalgo_initialized(metadata)) {
    cJSON_AddStringToObject(root, "encAlgo", metadata->encalgo.str);
  }

  if (atclient_atkey_metadata_is_ivnonce_initialized(metadata)) {
    cJSON_AddStringToObject(root, "ivNonce", metadata->ivnonce.str);
  }

  if (atclient_atkey_metadata_is_skeenckeyname_initialized(metadata)) {
    cJSON_AddStringToObject(root, "skeEncKeyName", metadata->skeenckeyname.str);
  }

  if (atclient_atkey_metadata_is_skeencalgo_initialized(metadata)) {
    cJSON_AddStringToObject(root, "skeEncAlgo", metadata->skeencalgo.str);
  }

  char *jsonstr = cJSON_Print(root);
  if (jsonstr == NULL) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "cJSON_Print failed\n");
    goto exit;
  }

  if (strlen(jsonstr) > metadatastrsize) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "metadatastr buffer too small: %lu > %lu\n", strlen(jsonstr),
                 metadatastrsize);
    free(jsonstr);
    goto exit;
  }

  strcpy(metadatastr, jsonstr);
  *metadatastrlen = strlen(jsonstr);
  free(jsonstr);

  ret = 0;
  goto exit;
exit: {
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
  return 15 // :dataSignature:
         + metadata->datasignature.len;
}

size_t atclient_atkey_metadata_sharedkeystatus_strlen(const atclient_atkey_metadata *metadata) {
  return 17 // :sharedKeyStatus:
         + metadata->sharedkeystatus.len;
}

size_t atclient_atkey_metadata_sharedkeyenc_strlen(const atclient_atkey_metadata *metadata) {
  return 14 // :sharedKeyEnc:
         + metadata->sharedkeyenc.len;
}

size_t atclient_atkey_metadata_pubkeyhash_strlen(const atclient_atkey_metadata *metadata) {
  return 6 // :hash:
         + metadata->pubkeyhash.len;
}

size_t atclient_atkey_metadata_pubkeyalgo_strlen(const atclient_atkey_metadata *metadata) {
  return 6 // :algo:
         + metadata->pubkeyalgo.len;
}

size_t atclient_atkey_metadata_encoding_strlen(const atclient_atkey_metadata *metadata) {
  return 10 // :encoding:
         + metadata->encoding.len;
}

size_t atclient_atkey_metadata_enckeyname_strlen(const atclient_atkey_metadata *metadata) {
  return 12 // :encKeyName:
         + metadata->enckeyname.len;
}

size_t atclient_atkey_metadata_encalgo_strlen(const atclient_atkey_metadata *metadata) {
  return 9 // :encAlgo:
         + metadata->encalgo.len;
}

size_t atclient_atkey_metadata_ivnonce_strlen(const atclient_atkey_metadata *metadata) {
  return 9 // :ivNonce:
         + metadata->ivnonce.len;
}

size_t atclient_atkey_metadata_skeenckeyname_strlen(const atclient_atkey_metadata *metadata) {
  return 15 // :skeEncKeyName:
         + metadata->skeenckeyname.len;
}

size_t atclient_atkey_metadata_skeencalgo_strlen(const atclient_atkey_metadata *metadata) {
  return 12 // :skeEncAlgo:
         + metadata->skeencalgo.len;
}

int atclient_atkey_metadata_to_protocol_str(const atclient_atkey_metadata *metadata, char *metadatastr,
                                            const size_t metadatastrsize, size_t *metadatastrlen) {
  int ret = 1;
  size_t pos = 0;
  size_t len = atclient_atkey_metadata_protocol_strlen(metadata);
  if (len > metadatastrsize) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "metadatastr buffer too small: %lu > %lu\n", len, metadatastrsize);
    return 1;
  }

  if (atclient_atkey_metadata_is_ttl_initialized(metadata)) {
    sprintf(metadatastr + pos, ":ttl:%ld", metadata->ttl);
    pos += 5 + long_strlen(metadata->ttl);
  }

  if (atclient_atkey_metadata_is_ttb_initialized(metadata)) {
    sprintf(metadatastr + pos, ":ttb:%ld", metadata->ttb);
    pos += 5 + long_strlen(metadata->ttb);
  }

  if (atclient_atkey_metadata_is_ttr_initialized(metadata)) {
    sprintf(metadatastr + pos, ":ttr:%ld", metadata->ttr);
    pos += 5 + long_strlen(metadata->ttr);
  }

  if (atclient_atkey_metadata_is_ccd_initialized(metadata)) {
    if (metadata->ccd) {
      sprintf(metadatastr + pos, ":ccd:true");
      pos += 9;
    } else {
      sprintf(metadatastr + pos, ":ccd:false");
      pos += 10;
    }
  }

  if (atclient_atkey_metadata_is_isbinary_initialized(metadata)) {
    if (metadata->isbinary) {
      sprintf(metadatastr + pos, ":isBinary:true");
      pos += 14;
    } else {
      sprintf(metadatastr + pos, ":isBinary:false");
      pos += 15;
    }
  }

  if (atclient_atkey_metadata_is_isencrypted_initialized(metadata)) {
    if (metadata->isencrypted) {
      sprintf(metadatastr + pos, ":isEncrypted:true");
      pos += 17;
    } else {
      sprintf(metadatastr + pos, ":isEncrypted:false");
      pos += 18;
    }
  }

  if (atclient_atkey_metadata_is_datasignature_initialized(metadata)) {
    sprintf(metadatastr + pos, ":dataSignature:%s", metadata->datasignature.str);
    pos += 15 + metadata->datasignature.len;
  }

  if (atclient_atkey_metadata_is_sharedkeystatus_initialized(metadata)) {
    sprintf(metadatastr + pos, ":sharedKeyStatus:%s", metadata->sharedkeystatus.str);
    pos += 17 + metadata->sharedkeystatus.len;
  }

  if (atclient_atkey_metadata_is_sharedkeyenc_initialized(metadata)) {
    sprintf(metadatastr + pos, ":sharedKeyEnc:%s", metadata->sharedkeyenc.str);
    pos += 14 + metadata->sharedkeyenc.len;
  }

  if (atclient_atkey_metadata_is_pubkeyhash_initialized(metadata)) {
    sprintf(metadatastr + pos, ":hash:%s", metadata->pubkeyhash.str);
    pos += 6 + metadata->pubkeyhash.len;
  }

  if (atclient_atkey_metadata_is_pubkeyalgo_initialized(metadata)) {
    sprintf(metadatastr + pos, ":algo:%s", metadata->pubkeyalgo.str);
    pos += 6 + metadata->pubkeyalgo.len;
  }

  if (atclient_atkey_metadata_is_encoding_initialized(metadata)) {
    sprintf(metadatastr + pos, ":encoding:%s", metadata->encoding.str);
    pos += 10 + metadata->encoding.len;
  }

  if (atclient_atkey_metadata_is_enckeyname_initialized(metadata)) {
    sprintf(metadatastr + pos, ":encKeyName:%s", metadata->enckeyname.str);
    pos += 12 + metadata->enckeyname.len;
  }

  if (atclient_atkey_metadata_is_encalgo_initialized(metadata)) {
    sprintf(metadatastr + pos, ":encAlgo:%s", metadata->encalgo.str);
    pos += 9 + metadata->encalgo.len;
  }

  if (atclient_atkey_metadata_is_ivnonce_initialized(metadata)) {
    sprintf(metadatastr + pos, ":ivNonce:%s", metadata->ivnonce.str);
    pos += 9 + metadata->ivnonce.len;
  }

  if (atclient_atkey_metadata_is_skeenckeyname_initialized(metadata)) {
    sprintf(metadatastr + pos, ":skeEncKeyName:%s", metadata->skeenckeyname.str);
    pos += 15 + metadata->skeenckeyname.len;
  }

  if (atclient_atkey_metadata_is_skeencalgo_initialized(metadata)) {
    sprintf(metadatastr + pos, ":skeEncAlgo:%s", metadata->skeencalgo.str);
    pos += 12 + metadata->skeencalgo.len;
  }

  if (strlen(metadatastr) != len) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "metadatastr length mismatch: %lu != %lu\n", strlen(metadatastr),
                 len);
    ret = 1;
    goto exit;
  }

  *metadatastrlen = len;

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

bool atclient_atkey_metadata_is_ishidden_initialized(const atclient_atkey_metadata *metadata) {
  return is_ishidden_initialized(metadata);
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

void atclient_atkey_metadata_set_ispublic(atclient_atkey_metadata *metadata, const bool ispublic) {
  if (is_ispublic_initialized(metadata)) {
    unset_ispublic(metadata);
  }
  set_ispublic(metadata, ispublic);
}

void atclient_atkey_metadata_set_ishidden(atclient_atkey_metadata *metadata, const bool ishidden) {
  if (is_ishidden_initialized(metadata)) {
    unset_ishidden(metadata);
  }
  set_ishidden(metadata, ishidden);
}

void atclient_atkey_metadata_set_iscached(atclient_atkey_metadata *metadata, const bool iscached) {
  if (is_iscached_initialized(metadata)) {
    unset_iscached(metadata);
  }
  set_iscached(metadata, iscached);
}

void atclient_atkey_metadata_set_ttl(atclient_atkey_metadata *metadata, const long ttl) {
  if (is_ttl_initialized(metadata)) {
    unset_ttl(metadata);
  }
  set_ttl(metadata, ttl);
}

void atclient_atkey_metadata_set_ttb(atclient_atkey_metadata *metadata, const long ttb) {
  if (is_ttb_initialized(metadata)) {
    unset_ttb(metadata);
  }
  set_ttb(metadata, ttb);
}

void atclient_atkey_metadata_set_ttr(atclient_atkey_metadata *metadata, const long ttr) {
  if (is_ttr_initialized(metadata)) {
    unset_ttr(metadata);
  }
  set_ttr(metadata, ttr);
}

void atclient_atkey_metadata_set_ccd(atclient_atkey_metadata *metadata, const bool ccd) {
  if (is_ccd_initialized(metadata)) {
    unset_ccd(metadata);
  }
  set_ccd(metadata, ccd);
}

void atclient_atkey_metadata_set_isbinary(atclient_atkey_metadata *metadata, const bool isbinary) {
  if (is_isbinary_initialized(metadata)) {
    unset_isbinary(metadata);
  }
  set_isbinary(metadata, isbinary);
}

void atclient_atkey_metadata_set_isencrypted(atclient_atkey_metadata *metadata, const bool isencrypted) {
  if (is_isencrypted_initialized(metadata)) {
    unset_isencrypted(metadata);
  }
  set_isencrypted(metadata, isencrypted);
}

int atclient_atkey_metadata_set_datasignature(atclient_atkey_metadata *metadata, const char *datasignature,
                                              const size_t datasignaturelen) {
  int ret = 1;
  if (is_datasignature_initialized(metadata)) {
    unset_datasignature(metadata);
  }
  if ((ret = set_datasignature(metadata, datasignature, datasignaturelen)) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "set_datasignature failed\n");
    goto exit;
  }
  ret = 0;
  goto exit;
exit: { return ret; }
}

int atclient_atkey_metadata_set_sharedkeystatus(atclient_atkey_metadata *metadata, const char *sharedkeystatus,
                                                const size_t sharedkeystatuslen) {
  int ret = 1;
  if (is_sharedkeystatus_initialized(metadata)) {
    unset_sharedkeystatus(metadata);
  }
  if ((ret = set_sharedkeystatus(metadata, sharedkeystatus, sharedkeystatuslen)) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "set_sharedkeystatus failed\n");
    goto exit;
  }
  ret = 0;
  goto exit;
exit: { return ret; }
}

int atclient_atkey_metadata_set_sharedkeyenc(atclient_atkey_metadata *metadata, const char *sharedkeyenc,
                                             const size_t sharedkeyenclen) {
  int ret = 1;
  if (is_sharedkeyenc_initialized(metadata)) {
    unset_sharedkeyenc(metadata);
  }
  if ((ret = set_sharedkeyenc(metadata, sharedkeyenc, sharedkeyenclen)) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "set_sharedkeyenc failed\n");
    goto exit;
  }
  ret = 0;
  goto exit;
exit: { return ret; }
}

int atclient_atkey_metadata_set_pubkeyhash(atclient_atkey_metadata *metadata, const char *pubkeyhash,
                                           const size_t pubkeyhashlen) {
  int ret = 1;
  if (is_pubkeyhash_initialized(metadata)) {
    unset_pubkeyhash(metadata);
  }
  if ((ret = set_pubkeyhash(metadata, pubkeyhash, pubkeyhashlen)) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "set_pubkeyhash failed\n");
    goto exit;
  }
  ret = 0;
  goto exit;
exit: { return ret; }
}

int atclient_atkey_metadata_set_pubkeyalgo(atclient_atkey_metadata *metadata, const char *pubkeyalgo,
                                           const size_t pubkeyalgolen) {
  int ret = 1;
  if (is_pubkeyalgo_initialized(metadata)) {
    unset_pubkeyalgo(metadata);
  }
  if ((ret = set_pubkeyalgo(metadata, pubkeyalgo, pubkeyalgolen)) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "set_pubkeyalgo failed\n");
    goto exit;
  }
  ret = 0;
  goto exit;
exit: { return ret; }
}

int atclient_atkey_metadata_set_encoding(atclient_atkey_metadata *metadata, const char *encoding,
                                         const size_t encodinglen) {
  int ret = 1;
  if (is_encoding_initialized(metadata)) {
    unset_encoding(metadata);
  }

  if ((ret = set_encoding(metadata, encoding, encodinglen)) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "set_encoding failed\n");
    goto exit;
  }
  ret = 0;
  goto exit;
exit: { return ret; }
}

int atclient_atkey_metadata_set_enckeyname(atclient_atkey_metadata *metadata, const char *enckeyname,
                                           const size_t enckeynamelen) {
  int ret = 1;
  if (is_enckeyname_initialized(metadata)) {
    unset_enckeyname(metadata);
  }
  if ((ret = set_enckeyname(metadata, enckeyname, enckeynamelen)) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "set_enckeyname failed\n");
    goto exit;
  }
  ret = 0;
  goto exit;
exit: { return ret; }
}

int atclient_atkey_metadata_set_encalgo(atclient_atkey_metadata *metadata, const char *encalgo,
                                        const size_t encalgolen) {
  int ret = 1;
  if (is_encalgo_initialized(metadata)) {
    unset_encalgo(metadata);
  }
  if ((ret = set_encalgo(metadata, encalgo, encalgolen)) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "set_encalgo failed\n");
    goto exit;
  }
  ret = 0;
  goto exit;
exit: { return ret; }
}

int atclient_atkey_metadata_set_ivnonce(atclient_atkey_metadata *metadata, const char *ivnonce,
                                        const size_t ivnoncelen) {
  int ret = 1;
  if (is_ivnonce_initialized(metadata)) {
    unset_ivnonce(metadata);
  }
  if ((ret = set_ivnonce(metadata, ivnonce, ivnoncelen)) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "set_ivnonce failed\n");
    goto exit;
  }
  ret = 0;
  goto exit;
exit: { return ret; }
}

int atclient_atkey_metadata_set_skeenckeyname(atclient_atkey_metadata *metadata, const char *skeenckeyname,
                                              const size_t skeenckeynamelen) {
  int ret = 1;
  if (is_skeenckeyname_initialized(metadata)) {
    unset_skeenckeyname(metadata);
  }
  if ((ret = set_skeenckeyname(metadata, skeenckeyname, skeenckeynamelen)) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "set_skeenckeyname failed\n");
    goto exit;
  }
  ret = 0;
  goto exit;
exit: { return ret; }
}

int atclient_atkey_metadata_set_skeencalgo(atclient_atkey_metadata *metadata, const char *skeencalgo,
                                           const size_t skeencalgolen) {
  int ret = 1;
  if (is_skeencalgo_initialized(metadata)) {
    unset_skeencalgo(metadata);
  }
  if ((ret = set_skeencalgo(metadata, skeencalgo, skeencalgolen)) != 0) {
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

  if (is_ishidden_initialized(metadata)) {
    unset_ishidden(metadata);
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
  return (metadata->initializedfields[ATKEY_METADATA_CREATEDBY_INDEX] & ATKEY_METADATA_CREATEDBY_INITIALIZED);
}

static bool is_updatedby_initialized(const atclient_atkey_metadata *metadata) {
  return (metadata->initializedfields[ATKEY_METADATA_UPDATEDBY_INDEX] & ATKEY_METADATA_UPDATEDBY_INITIALIZED);
}

static bool is_status_initialized(const atclient_atkey_metadata *metadata) {
  return (metadata->initializedfields[ATKEY_METADATA_STATUS_INDEX] & ATKEY_METADATA_STATUS_INITIALIZED);
}

static bool is_version_initialized(const atclient_atkey_metadata *metadata) {
  return (metadata->initializedfields[ATKEY_METADATA_VERSION_INDEX] & ATKEY_METADATA_VERSION_INITIALIZED);
}

static bool is_expiresat_initialized(const atclient_atkey_metadata *metadata) {
  return (metadata->initializedfields[ATKEY_METADATA_EXPIRESAT_INDEX] & ATKEY_METADATA_EXPIRESAT_INITIALIZED);
}

static bool is_availableat_initialized(const atclient_atkey_metadata *metadata) {
  return (metadata->initializedfields[ATKEY_METADATA_AVAILABLEAT_INDEX] & ATKEY_METADATA_AVAILABLEAT_INITIALIZED);
}

static bool is_refreshat_initialized(const atclient_atkey_metadata *metadata) {
  return (metadata->initializedfields[ATKEY_METADATA_REFRESHAT_INDEX] & ATKEY_METADATA_REFRESHAT_INITIALIZED);
}

static bool is_createdat_initialized(const atclient_atkey_metadata *metadata) {
  return (metadata->initializedfields[ATKEY_METADATA_CREATEDAT_INDEX] & ATKEY_METADATA_CREATEDAT_INITIALIZED);
}

static bool is_updatedat_initialized(const atclient_atkey_metadata *metadata) {
  return (metadata->initializedfields[ATKEY_METADATA_UPDATEDAT_INDEX] & ATKEY_METADATA_UPDATEDAT_INITIALIZED);
}

static bool is_ispublic_initialized(const atclient_atkey_metadata *metadata) {
  return (metadata->initializedfields[ATKEY_METADATA_ISPUBLIC_INDEX] & ATKEY_METADATA_ISPUBLIC_INITIALIZED);
}

static bool is_ishidden_initialized(const atclient_atkey_metadata *metadata) {
  return (metadata->initializedfields[ATKEY_METADATA_ISHIDDEN_INDEX] & ATKEY_METADATA_ISHIDDEN_INITIALIZED);
}

static bool is_iscached_initialized(const atclient_atkey_metadata *metadata) {
  return (metadata->initializedfields[ATKEY_METADATA_ISCACHED_INDEX] & ATKEY_METADATA_ISCACHED_INITIALIZED);
}

static bool is_ttl_initialized(const atclient_atkey_metadata *metadata) {
  return (metadata->initializedfields[ATKEY_METADATA_TTL_INDEX] & ATKEY_METADATA_TTL_INITIALIZED);
}

static bool is_ttb_initialized(const atclient_atkey_metadata *metadata) {
  return (metadata->initializedfields[ATKEY_METADATA_TTB_INDEX] & ATKEY_METADATA_TTB_INITIALIZED);
}

static bool is_ttr_initialized(const atclient_atkey_metadata *metadata) {
  return (metadata->initializedfields[ATKEY_METADATA_TTR_INDEX] & ATKEY_METADATA_TTR_INITIALIZED);
}

static bool is_ccd_initialized(const atclient_atkey_metadata *metadata) {
  return (metadata->initializedfields[ATKEY_METADATA_CCD_INDEX] & ATKEY_METADATA_CCD_INITIALIZED);
}

static bool is_isbinary_initialized(const atclient_atkey_metadata *metadata) {
  return (metadata->initializedfields[ATKEY_METADATA_ISBINARY_INDEX] & ATKEY_METADATA_ISBINARY_INITIALIZED);
}

static bool is_isencrypted_initialized(const atclient_atkey_metadata *metadata) {
  return (metadata->initializedfields[ATKEY_METADATA_ISENCRYPTED_INDEX] & ATKEY_METADATA_ISENCRYPTED_INITIALIZED);
}

static bool is_datasignature_initialized(const atclient_atkey_metadata *metadata) {
  return (metadata->initializedfields[ATKEY_METADATA_DATASIGNATURE_INDEX] & ATKEY_METADATA_DATASIGNATURE_INITIALIZED);
}

static bool is_sharedkeystatus_initialized(const atclient_atkey_metadata *metadata) {
  return (metadata->initializedfields[ATKEY_METADATA_SHAREDKEYSTATUS_INDEX] &
          ATKEY_METADATA_SHAREDKEYSTATUS_INITIALIZED);
}

static bool is_sharedkeyenc_initialized(const atclient_atkey_metadata *metadata) {
  return (metadata->initializedfields[ATKEY_METADATA_SHAREDKEYENC_INDEX] & ATKEY_METADATA_SHAREDKEYENC_INITIALIZED);
}

static bool is_pubkeyhash_initialized(const atclient_atkey_metadata *metadata) {
  return (metadata->initializedfields[ATKEY_METADATA_PUBKEYHASH_INDEX] & ATKEY_METADATA_PUBKEYHASH_INITIALIZED);
}

static bool is_pubkeyalgo_initialized(const atclient_atkey_metadata *metadata) {
  return (metadata->initializedfields[ATKEY_METADATA_PUBKEYALGO_INDEX] & ATKEY_METADATA_PUBKEYALGO_INITIALIZED);
}

static bool is_encoding_initialized(const atclient_atkey_metadata *metadata) {
  return (metadata->initializedfields[ATKEY_METADATA_ENCODING_INDEX] & ATKEY_METADATA_ENCODING_INITIALIZED);
}

static bool is_enckeyname_initialized(const atclient_atkey_metadata *metadata) {
  return (metadata->initializedfields[ATKEY_METADATA_ENCKEYNAME_INDEX] & ATKEY_METADATA_ENCKEYNAME_INITIALIZED);
}

static bool is_encalgo_initialized(const atclient_atkey_metadata *metadata) {
  return (metadata->initializedfields[ATKEY_METADATA_ENCALGO_INDEX] & ATKEY_METADATA_ENCALGO_INITIALIZED);
}

static bool is_ivnonce_initialized(const atclient_atkey_metadata *metadata) {
  return (metadata->initializedfields[ATKEY_METADATA_IVNONCE_INDEX] & ATKEY_METADATA_IVNONCE_INITIALIZED);
}

static bool is_skeenckeyname_initialized(const atclient_atkey_metadata *metadata) {
  return (metadata->initializedfields[ATKEY_METADATA_SKEENCKEYNAME_INDEX] & ATKEY_METADATA_SKEENCKEYNAME_INITIALIZED);
}

static bool is_skeencalgo_initialized(const atclient_atkey_metadata *metadata) {
  return (metadata->initializedfields[ATKEY_METADATA_SKEENCALGO_INDEX] & ATKEY_METADATA_SKEENCALGO_INITIALIZED);
}

static void set_is_createdby_initialized(atclient_atkey_metadata *metadata, bool is_initialized) {
  if (is_initialized) {
    metadata->initializedfields[ATKEY_METADATA_CREATEDBY_INDEX] |= ATKEY_METADATA_CREATEDBY_INITIALIZED;
  } else {
    metadata->initializedfields[ATKEY_METADATA_CREATEDBY_INDEX] &= ~ATKEY_METADATA_CREATEDBY_INITIALIZED;
  }
}

static void set_is_updatedby_initialized(atclient_atkey_metadata *metadata, bool is_initialized) {
  if (is_initialized) {
    metadata->initializedfields[ATKEY_METADATA_UPDATEDBY_INDEX] |= ATKEY_METADATA_UPDATEDBY_INITIALIZED;
  } else {
    metadata->initializedfields[ATKEY_METADATA_UPDATEDBY_INDEX] &= ~ATKEY_METADATA_UPDATEDBY_INITIALIZED;
  }
}

static void set_is_status_initialized(atclient_atkey_metadata *metadata, bool is_initialized) {
  if (is_initialized) {
    metadata->initializedfields[ATKEY_METADATA_STATUS_INDEX] |= ATKEY_METADATA_STATUS_INITIALIZED;
  } else {
    metadata->initializedfields[ATKEY_METADATA_STATUS_INDEX] &= ~ATKEY_METADATA_STATUS_INITIALIZED;
  }
}

static void set_is_version_initialized(atclient_atkey_metadata *metadata, bool is_initialized) {
  if (is_initialized) {
    metadata->initializedfields[ATKEY_METADATA_VERSION_INDEX] |= ATKEY_METADATA_VERSION_INITIALIZED;
  } else {
    metadata->initializedfields[ATKEY_METADATA_VERSION_INDEX] &= ~ATKEY_METADATA_VERSION_INITIALIZED;
  }
}

static void set_is_expiresat_initialized(atclient_atkey_metadata *metadata, bool is_initialized) {
  if (is_initialized) {
    metadata->initializedfields[ATKEY_METADATA_EXPIRESAT_INDEX] |= ATKEY_METADATA_EXPIRESAT_INITIALIZED;
  } else {
    metadata->initializedfields[ATKEY_METADATA_EXPIRESAT_INDEX] &= ~ATKEY_METADATA_EXPIRESAT_INITIALIZED;
  }
}

static void set_is_availableat_initialized(atclient_atkey_metadata *metadata, bool is_initialized) {
  if (is_initialized) {
    metadata->initializedfields[ATKEY_METADATA_AVAILABLEAT_INDEX] |= ATKEY_METADATA_AVAILABLEAT_INITIALIZED;
  } else {
    metadata->initializedfields[ATKEY_METADATA_AVAILABLEAT_INDEX] &= ~ATKEY_METADATA_AVAILABLEAT_INITIALIZED;
  }
}

static void set_is_refreshat_initialized(atclient_atkey_metadata *metadata, bool is_initialized) {
  if (is_initialized) {
    metadata->initializedfields[ATKEY_METADATA_REFRESHAT_INDEX] |= ATKEY_METADATA_REFRESHAT_INITIALIZED;
  } else {
    metadata->initializedfields[ATKEY_METADATA_REFRESHAT_INDEX] &= ~ATKEY_METADATA_REFRESHAT_INITIALIZED;
  }
}

static void set_is_createdat_initialized(atclient_atkey_metadata *metadata, bool is_initialized) {
  if (is_initialized) {
    metadata->initializedfields[ATKEY_METADATA_CREATEDAT_INDEX] |= ATKEY_METADATA_CREATEDAT_INITIALIZED;
  } else {
    metadata->initializedfields[ATKEY_METADATA_CREATEDAT_INDEX] &= ~ATKEY_METADATA_CREATEDAT_INITIALIZED;
  }
}

static void set_is_updatedat_initialized(atclient_atkey_metadata *metadata, bool is_initialized) {
  if (is_initialized) {
    metadata->initializedfields[ATKEY_METADATA_UPDATEDAT_INDEX] |= ATKEY_METADATA_UPDATEDAT_INITIALIZED;
  } else {
    metadata->initializedfields[ATKEY_METADATA_UPDATEDAT_INDEX] &= ~ATKEY_METADATA_UPDATEDAT_INITIALIZED;
  }
}

static void set_is_ispublic_initialized(atclient_atkey_metadata *metadata, bool is_initialized) {
  if (is_initialized) {
    metadata->initializedfields[ATKEY_METADATA_ISPUBLIC_INDEX] |= ATKEY_METADATA_ISPUBLIC_INITIALIZED;
  } else {
    metadata->initializedfields[ATKEY_METADATA_ISPUBLIC_INDEX] &= ~ATKEY_METADATA_ISPUBLIC_INITIALIZED;
  }
}

static void set_is_ishidden_initialized(atclient_atkey_metadata *metadata, bool is_initialized) {
  if (is_initialized) {
    metadata->initializedfields[ATKEY_METADATA_ISHIDDEN_INDEX] |= ATKEY_METADATA_ISHIDDEN_INITIALIZED;
  } else {
    metadata->initializedfields[ATKEY_METADATA_ISHIDDEN_INDEX] &= ~ATKEY_METADATA_ISHIDDEN_INITIALIZED;
  }
}

static void set_is_iscached_initialized(atclient_atkey_metadata *metadata, bool is_initialized) {
  if (is_initialized) {
    metadata->initializedfields[ATKEY_METADATA_ISCACHED_INDEX] |= ATKEY_METADATA_ISCACHED_INITIALIZED;
  } else {
    metadata->initializedfields[ATKEY_METADATA_ISCACHED_INDEX] &= ~ATKEY_METADATA_ISCACHED_INITIALIZED;
  }
}

static void set_is_ttl_initialized(atclient_atkey_metadata *metadata, bool is_initialized) {
  if (is_initialized) {
    metadata->initializedfields[ATKEY_METADATA_TTL_INDEX] |= ATKEY_METADATA_TTL_INITIALIZED;
  } else {
    metadata->initializedfields[ATKEY_METADATA_TTL_INDEX] &= ~ATKEY_METADATA_TTL_INITIALIZED;
  }
}

static void set_is_ttb_initialized(atclient_atkey_metadata *metadata, bool is_initialized) {
  if (is_initialized) {
    metadata->initializedfields[ATKEY_METADATA_TTB_INDEX] |= ATKEY_METADATA_TTB_INITIALIZED;
  } else {
    metadata->initializedfields[ATKEY_METADATA_TTB_INDEX] &= ~ATKEY_METADATA_TTB_INITIALIZED;
  }
}

static void set_is_ttr_initialized(atclient_atkey_metadata *metadata, bool is_initialized) {
  if (is_initialized) {
    metadata->initializedfields[ATKEY_METADATA_TTR_INDEX] |= ATKEY_METADATA_TTR_INITIALIZED;
  } else {
    metadata->initializedfields[ATKEY_METADATA_TTR_INDEX] &= ~ATKEY_METADATA_TTR_INITIALIZED;
  }
}

static void set_is_ccd_initialized(atclient_atkey_metadata *metadata, bool is_initialized) {
  if (is_initialized) {
    metadata->initializedfields[ATKEY_METADATA_CCD_INDEX] |= ATKEY_METADATA_CCD_INITIALIZED;
  } else {
    metadata->initializedfields[ATKEY_METADATA_CCD_INDEX] &= ~ATKEY_METADATA_CCD_INITIALIZED;
  }
}

static void set_is_isbinary_initialized(atclient_atkey_metadata *metadata, bool is_initialized) {
  if (is_initialized) {
    metadata->initializedfields[ATKEY_METADATA_ISBINARY_INDEX] |= ATKEY_METADATA_ISBINARY_INITIALIZED;
  } else {
    metadata->initializedfields[ATKEY_METADATA_ISBINARY_INDEX] &= ~ATKEY_METADATA_ISBINARY_INITIALIZED;
  }
}

static void set_is_isencrypted_initialized(atclient_atkey_metadata *metadata, bool is_initialized) {
  if (is_initialized) {
    metadata->initializedfields[ATKEY_METADATA_ISENCRYPTED_INDEX] |= ATKEY_METADATA_ISENCRYPTED_INITIALIZED;
  } else {
    metadata->initializedfields[ATKEY_METADATA_ISENCRYPTED_INDEX] &= ~ATKEY_METADATA_ISENCRYPTED_INITIALIZED;
  }
}

static void set_is_datasignature_initialized(atclient_atkey_metadata *metadata, bool is_initialized) {
  if (is_initialized) {
    metadata->initializedfields[ATKEY_METADATA_DATASIGNATURE_INDEX] |= ATKEY_METADATA_DATASIGNATURE_INITIALIZED;
  } else {
    metadata->initializedfields[ATKEY_METADATA_DATASIGNATURE_INDEX] &= ~ATKEY_METADATA_DATASIGNATURE_INITIALIZED;
  }
}

static void set_is_sharedkeystatus_initialized(atclient_atkey_metadata *metadata, bool is_initialized) {
  if (is_initialized) {
    metadata->initializedfields[ATKEY_METADATA_SHAREDKEYSTATUS_INDEX] |= ATKEY_METADATA_SHAREDKEYSTATUS_INITIALIZED;
  } else {
    metadata->initializedfields[ATKEY_METADATA_SHAREDKEYSTATUS_INDEX] &= ~ATKEY_METADATA_SHAREDKEYSTATUS_INITIALIZED;
  }
}

static void set_is_sharedkeyenc_initialized(atclient_atkey_metadata *metadata, bool is_initialized) {
  if (is_initialized) {
    metadata->initializedfields[ATKEY_METADATA_SHAREDKEYENC_INDEX] |= ATKEY_METADATA_SHAREDKEYENC_INITIALIZED;
  } else {
    metadata->initializedfields[ATKEY_METADATA_SHAREDKEYENC_INDEX] &= ~ATKEY_METADATA_SHAREDKEYENC_INITIALIZED;
  }
}

static void set_is_pubkeyhash_initialized(atclient_atkey_metadata *metadata, bool is_initialized) {
  if (is_initialized) {
    metadata->initializedfields[ATKEY_METADATA_PUBKEYHASH_INDEX] |= ATKEY_METADATA_PUBKEYHASH_INITIALIZED;
  } else {
    metadata->initializedfields[ATKEY_METADATA_PUBKEYHASH_INDEX] &= ~ATKEY_METADATA_PUBKEYHASH_INITIALIZED;
  }
}

static void set_is_pubkeyalgo_initialized(atclient_atkey_metadata *metadata, bool is_initialized) {
  if (is_initialized) {
    metadata->initializedfields[ATKEY_METADATA_PUBKEYALGO_INDEX] |= ATKEY_METADATA_PUBKEYALGO_INITIALIZED;
  } else {
    metadata->initializedfields[ATKEY_METADATA_PUBKEYALGO_INDEX] &= ~ATKEY_METADATA_PUBKEYALGO_INITIALIZED;
  }
}

static void set_is_encoding_initialized(atclient_atkey_metadata *metadata, bool is_initialized) {
  if (is_initialized) {
    metadata->initializedfields[ATKEY_METADATA_ENCODING_INDEX] |= ATKEY_METADATA_ENCODING_INITIALIZED;
  } else {
    metadata->initializedfields[ATKEY_METADATA_ENCODING_INDEX] &= ~ATKEY_METADATA_ENCODING_INITIALIZED;
  }
}

static void set_is_enckeyname_initialized(atclient_atkey_metadata *metadata, bool is_initialized) {
  if (is_initialized) {
    metadata->initializedfields[ATKEY_METADATA_ENCKEYNAME_INDEX] |= ATKEY_METADATA_ENCKEYNAME_INITIALIZED;
  } else {
    metadata->initializedfields[ATKEY_METADATA_ENCKEYNAME_INDEX] &= ~ATKEY_METADATA_ENCKEYNAME_INITIALIZED;
  }
}

static void set_is_encalgo_initialized(atclient_atkey_metadata *metadata, bool is_initialized) {
  if (is_initialized) {
    metadata->initializedfields[ATKEY_METADATA_ENCALGO_INDEX] |= ATKEY_METADATA_ENCALGO_INITIALIZED;
  } else {
    metadata->initializedfields[ATKEY_METADATA_ENCALGO_INDEX] &= ~ATKEY_METADATA_ENCALGO_INITIALIZED;
  }
}

static void set_is_ivnonce_initialized(atclient_atkey_metadata *metadata, bool is_initialized) {
  if (is_initialized) {
    metadata->initializedfields[ATKEY_METADATA_IVNONCE_INDEX] |= ATKEY_METADATA_IVNONCE_INITIALIZED;
  } else {
    metadata->initializedfields[ATKEY_METADATA_IVNONCE_INDEX] &= ~ATKEY_METADATA_IVNONCE_INITIALIZED;
  }
}

static void set_is_skeenckeyname_initialized(atclient_atkey_metadata *metadata, bool is_initialized) {
  if (is_initialized) {
    metadata->initializedfields[ATKEY_METADATA_SKEENCKEYNAME_INDEX] |= ATKEY_METADATA_SKEENCKEYNAME_INITIALIZED;
  } else {
    metadata->initializedfields[ATKEY_METADATA_SKEENCKEYNAME_INDEX] &= ~ATKEY_METADATA_SKEENCKEYNAME_INITIALIZED;
  }
}

static void set_is_skeencalgo_initialized(atclient_atkey_metadata *metadata, bool is_initialized) {
  if (is_initialized) {
    metadata->initializedfields[ATKEY_METADATA_SKEENCALGO_INDEX] |= ATKEY_METADATA_SKEENCALGO_INITIALIZED;
  } else {
    metadata->initializedfields[ATKEY_METADATA_SKEENCALGO_INDEX] &= ~ATKEY_METADATA_SKEENCALGO_INITIALIZED;
  }
}

static void unset_createdby(atclient_atkey_metadata *metadata) {
  atclient_atsign_free(&metadata->createdby);
  set_is_createdby_initialized(metadata, false);
}

static void unset_updatedby(atclient_atkey_metadata *metadata) {
  atclient_atsign_free(&metadata->updatedby);
  set_is_updatedby_initialized(metadata, false);
}

static void unset_status(atclient_atkey_metadata *metadata) {
  atclient_atstr_free(&metadata->status);
  set_is_status_initialized(metadata, false);
}

static void unset_version(atclient_atkey_metadata *metadata) {
  metadata->version = 0;
  set_is_version_initialized(metadata, false);
}

static void unset_expiresat(atclient_atkey_metadata *metadata) {
  atclient_atstr_free(&metadata->expiresat);
  set_is_expiresat_initialized(metadata, false);
}

static void unset_availableat(atclient_atkey_metadata *metadata) {
  atclient_atstr_free(&metadata->availableat);
  set_is_availableat_initialized(metadata, false);
}

static void unset_refreshat(atclient_atkey_metadata *metadata) {
  atclient_atstr_free(&metadata->refreshat);
  set_is_refreshat_initialized(metadata, false);
}

static void unset_createdat(atclient_atkey_metadata *metadata) {
  atclient_atstr_free(&metadata->createdat);
  set_is_createdat_initialized(metadata, false);
}

static void unset_updatedat(atclient_atkey_metadata *metadata) {
  atclient_atstr_free(&metadata->updatedat);
  set_is_updatedat_initialized(metadata, false);
}

static void unset_ispublic(atclient_atkey_metadata *metadata) {
  metadata->ispublic = false;
  set_is_ispublic_initialized(metadata, false);
}

static void unset_ishidden(atclient_atkey_metadata *metadata) {
  metadata->ishidden = false;
  set_is_ishidden_initialized(metadata, false);
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
  atclient_atstr_free(&metadata->datasignature);
  set_is_datasignature_initialized(metadata, false);
}

static void unset_sharedkeystatus(atclient_atkey_metadata *metadata) {
  atclient_atstr_free(&metadata->sharedkeystatus);
  set_is_sharedkeystatus_initialized(metadata, false);
}

static void unset_sharedkeyenc(atclient_atkey_metadata *metadata) {
  atclient_atstr_free(&metadata->sharedkeyenc);
  set_is_sharedkeyenc_initialized(metadata, false);
}

static void unset_pubkeyhash(atclient_atkey_metadata *metadata) {
  atclient_atstr_free(&metadata->pubkeyhash);
  set_is_pubkeyhash_initialized(metadata, false);
}

static void unset_pubkeyalgo(atclient_atkey_metadata *metadata) {
  atclient_atstr_free(&metadata->pubkeyalgo);
  set_is_pubkeyalgo_initialized(metadata, false);
}

static void unset_encoding(atclient_atkey_metadata *metadata) {
  atclient_atstr_free(&metadata->encoding);
  set_is_encoding_initialized(metadata, false);
}

static void unset_enckeyname(atclient_atkey_metadata *metadata) {
  atclient_atstr_free(&metadata->enckeyname);
  set_is_enckeyname_initialized(metadata, false);
}

static void unset_encalgo(atclient_atkey_metadata *metadata) {
  if (atclient_atkey_metadata_is_encalgo_initialized(metadata)) {
    atclient_atstr_free(&metadata->encalgo);
  }
  set_is_encalgo_initialized(metadata, false);
}

static void unset_ivnonce(atclient_atkey_metadata *metadata) {
  atclient_atstr_free(&metadata->ivnonce);
  set_is_ivnonce_initialized(metadata, false);
}

static void unset_skeenckeyname(atclient_atkey_metadata *metadata) {
  atclient_atstr_free(&metadata->skeenckeyname);
  set_is_skeenckeyname_initialized(metadata, false);
}

static void unset_skeencalgo(atclient_atkey_metadata *metadata) {
  atclient_atstr_free(&metadata->skeencalgo);
  set_is_skeencalgo_initialized(metadata, false);
}

static int set_createdby(atclient_atkey_metadata *metadata, const char *createdby, const size_t createdbylen) {
  int ret = 1;
  if ((ret = atclient_atsign_init(&metadata->createdby, createdby)) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atclient_atsign_init failed with string \"%.*s\"\n", createdbylen,
                 createdby);
    goto exit;
  }
  set_is_createdby_initialized(metadata, true);
  ret = 0;
  goto exit;
exit: { return ret; }
}

static int set_updatedby(atclient_atkey_metadata *metadata, const char *updatedby, const size_t updatedbylen) {
  int ret = 1;
  if ((ret = atclient_atsign_init(&metadata->updatedby, updatedby)) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atclient_atsign_init failed with string \"%.*s\"\n", updatedbylen,
                 updatedby);
    goto exit;
  }
  set_is_updatedby_initialized(metadata, true);
  ret = 0;
  goto exit;
exit: { return ret; }
}

static int set_status(atclient_atkey_metadata *metadata, const char *status, const size_t statuslen) {
  int ret = 1;
  if ((ret = atclient_atstr_init_literal(&metadata->status, statuslen + 1, status)) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atclient_atstr_init_literal failed with string \"%.*s\"\n",
                 statuslen, status);
    goto exit;
  }
  set_is_status_initialized(metadata, true);
  ret = 0;
  goto exit;
exit: { return ret; }
}

static void set_version(atclient_atkey_metadata *metadata, int version) {
  metadata->version = version;
  set_is_version_initialized(metadata, true);
}

static int set_expiresat(atclient_atkey_metadata *metadata, const char *expiresat, const size_t expiresatlen) {
  int ret = 1;
  if ((ret = atclient_atstr_init_literal(&metadata->expiresat, expiresatlen + 1, expiresat)) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atclient_atstr_init_literal failed with string \"%.*s\"\n",
                 expiresatlen, expiresat);
    goto exit;
  }
  set_is_expiresat_initialized(metadata, true);
  ret = 0;
  goto exit;
exit: { return ret; }
}

static int set_availableat(atclient_atkey_metadata *metadata, const char *availableat, const size_t availableatlen) {
  int ret = 1;
  if ((ret = atclient_atstr_init_literal(&metadata->availableat, availableatlen + 1, availableat)) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atclient_atstr_init_literal failed with string \"%.*s\"\n",
                 availableatlen, availableat);
    goto exit;
  }
  set_is_availableat_initialized(metadata, true);
  ret = 0;
  goto exit;
exit: { return ret; }
}

static int set_refreshat(atclient_atkey_metadata *metadata, const char *refreshat, const size_t refreshatlen) {
  int ret = 1;
  if ((ret = atclient_atstr_init_literal(&metadata->refreshat, refreshatlen + 1, refreshat)) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atclient_atstr_init_literal failed with string \"%.*s\"\n",
                 refreshatlen, refreshat);
    goto exit;
  }
  set_is_refreshat_initialized(metadata, true);
  ret = 0;
  goto exit;
exit: { return ret; }
}

static int set_createdat(atclient_atkey_metadata *metadata, const char *createdat, const size_t createdatlen) {
  int ret = 1;
  if ((ret = atclient_atstr_init_literal(&metadata->createdat, createdatlen + 1, createdat)) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atclient_atstr_init_literal failed with string \"%.*s\"\n",
                 createdatlen, createdat);
    goto exit;
  }
  set_is_createdat_initialized(metadata, true);
  ret = 0;
  goto exit;
exit: { return ret; }
}

static int set_updatedat(atclient_atkey_metadata *metadata, const char *updatedat, const size_t updatedatlen) {
  int ret = 1;
  if ((ret = atclient_atstr_init_literal(&metadata->updatedat, updatedatlen + 1, updatedat)) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atclient_atstr_init_literal failed with string \"%.*s\"\n",
                 updatedatlen, updatedat);
    goto exit;
  }
  set_is_updatedat_initialized(metadata, true);
  ret = 0;
  goto exit;
exit: { return ret; }
}

static void set_ispublic(atclient_atkey_metadata *metadata, const bool ispublic) {
  metadata->ispublic = ispublic;
  set_is_ispublic_initialized(metadata, true);
}

static void set_ishidden(atclient_atkey_metadata *metadata, const bool ishidden) {
  metadata->ishidden = ishidden;
  set_is_ishidden_initialized(metadata, true);
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

static int set_datasignature(atclient_atkey_metadata *metadata, const char *datasignature,
                             const size_t datasignaturelen) {
  int ret = 1;
  if ((ret = atclient_atstr_init_literal(&metadata->datasignature, datasignaturelen + 1, datasignature)) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atclient_atstr_init_literal failed with string \"%.*s\"\n",
                 datasignaturelen, datasignature);
    goto exit;
  }
  set_is_datasignature_initialized(metadata, true);
  ret = 0;
  goto exit;
exit: { return ret; }
}

static int set_sharedkeystatus(atclient_atkey_metadata *metadata, const char *sharedkeystatus,
                               const size_t sharedkeystatuslen) {
  int ret = 1;
  if ((ret = atclient_atstr_init_literal(&metadata->sharedkeystatus, sharedkeystatuslen + 1, sharedkeystatus)) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atclient_atstr_init_literal failed with string \"%.*s\"\n",
                 sharedkeystatuslen, sharedkeystatus);
    goto exit;
  }
  set_is_sharedkeystatus_initialized(metadata, true);
  ret = 0;
  goto exit;
exit: { return ret; }
}

static int set_sharedkeyenc(atclient_atkey_metadata *metadata, const char *sharedkeyenc, const size_t sharedkeyenclen) {
  int ret = 1;
  if ((ret = atclient_atstr_init_literal(&metadata->sharedkeyenc, sharedkeyenclen + 1, sharedkeyenc)) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atclient_atstr_init_literal failed with string \"%.*s\"\n",
                 sharedkeyenclen + 1, sharedkeyenc);
    goto exit;
  }
  set_is_sharedkeyenc_initialized(metadata, true);
  ret = 0;
  goto exit;
exit: { return ret; }
}

static int set_pubkeyhash(atclient_atkey_metadata *metadata, const char *pubkeyhash, const size_t pubkeyhashlen) {
  int ret = 1;
  if ((ret = atclient_atstr_init_literal(&metadata->pubkeyhash, pubkeyhashlen + 1, pubkeyhash)) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atclient_atstr_init_literal failed with string \"%.*s\"\n",
                 pubkeyhashlen, pubkeyhash);
    goto exit;
  }
  set_is_pubkeyhash_initialized(metadata, true);
  ret = 0;
  goto exit;
exit: { return ret; }
}

static int set_pubkeyalgo(atclient_atkey_metadata *metadata, const char *pubkeyalgo, const size_t pubkeyalgolen) {
  int ret = 1;
  if ((ret = atclient_atstr_init_literal(&metadata->pubkeyalgo, pubkeyalgolen + 1, pubkeyalgo)) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atclient_atstr_init_literal failed with string \"%.*s\"\n",
                 pubkeyalgolen, pubkeyalgo);
    goto exit;
  }
  set_is_pubkeyalgo_initialized(metadata, true);
  ret = 0;
  goto exit;
exit: { return ret; }
}

static int set_encoding(atclient_atkey_metadata *metadata, const char *encoding, const size_t encodinglen) {
  int ret = 1;
  if ((ret = atclient_atstr_init_literal(&metadata->encoding, encodinglen + 1, encoding)) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atclient_atstr_init_literal failed with string \"%.*s\"\n",
                 encodinglen, encoding);
    goto exit;
  }
  set_is_encoding_initialized(metadata, true);
  ret = 0;
  goto exit;
exit: { return ret; }
}

static int set_enckeyname(atclient_atkey_metadata *metadata, const char *enckeyname, const size_t enckeynamelen) {
  int ret = 1;
  if ((ret = atclient_atstr_init_literal(&metadata->enckeyname, enckeynamelen + 1, enckeyname)) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atclient_atstr_init_literal failed with string \"%.*s\"\n",
                 enckeynamelen, enckeyname);
    goto exit;
  }
  set_is_enckeyname_initialized(metadata, true);
  ret = 0;
  goto exit;
exit: { return ret; }
}

static int set_encalgo(atclient_atkey_metadata *metadata, const char *encalgo, const size_t encalgolen) {
  int ret = 1;
  if ((ret = atclient_atstr_init_literal(&metadata->encalgo, encalgolen + 1, encalgo)) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atclient_atstr_init_literal failed with string \"%.*s\"\n",
                 encalgolen, encalgo);
    goto exit;
  }
  set_is_encalgo_initialized(metadata, true);
  ret = 0;
  goto exit;
exit: { return ret; }
}

static int set_ivnonce(atclient_atkey_metadata *metadata, const char *ivnonce, const size_t ivnoncelen) {
  int ret = 1;
  if ((ret = atclient_atstr_init_literal(&metadata->ivnonce, ivnoncelen + 1, ivnonce)) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atclient_atstr_init_literal failed with string \"%.*s\"\n",
                 ivnoncelen, ivnonce);
    goto exit;
  }
  set_is_ivnonce_initialized(metadata, true);
  ret = 0;
  goto exit;
exit: { return ret; }
}

static int set_skeenckeyname(atclient_atkey_metadata *metadata, const char *skeenckeyname,
                             const size_t skeenckeynamelen) {
  int ret = 1;
  if ((ret = atclient_atstr_init_literal(&metadata->skeenckeyname, skeenckeynamelen + 1, skeenckeyname)) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atclient_atstr_init_literal failed with string \"%.*s\"\n",
                 skeenckeynamelen, skeenckeyname);
    goto exit;
  }
  set_is_skeenckeyname_initialized(metadata, true);
  ret = 0;
  goto exit;
exit: { return ret; }
}

static int set_skeencalgo(atclient_atkey_metadata *metadata, const char *skeencalgo, const size_t skeencalgolen) {
  int ret = 1;
  if ((ret = atclient_atstr_init_literal(&metadata->skeencalgo, skeencalgolen + 1, skeencalgo)) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atclient_atstr_init_literal failed with string \"%.*s\"\n",
                 skeencalgolen, skeencalgo);
    goto exit;
  }
  set_is_skeencalgo_initialized(metadata, true);
  ret = 0;
  goto exit;
exit: { return ret; }
}
