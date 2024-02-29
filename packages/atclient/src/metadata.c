#include "atclient/metadata.h"
#include "atclient/atsign.h"
#include "atclient/atstr.h"
#include "atclient/stringutils.h"
#include "atlogger/atlogger.h"
#include "cJSON/cJSON.h"
#include <stdlib.h>
#include <string.h>

#define TAG "metadata"

static int set_createdby(atclient_atkey_metadata *metadata, const char *createdby, const size_t createdbylen) {
  int ret = 1;
  if (atclient_atkey_metadata_is_createdby_initialized(metadata)) {
    atclient_atsign_free(&metadata->createdby);
  }
  atclient_atsign_init(&metadata->createdby, createdby);
  metadata->initializedfields[0] |= ATKEY_METADATA_CREATEDBY_INITIALIZED;
  ret = 0;
  goto exit;
exit: { return ret; }
}

static int set_updatedby(atclient_atkey_metadata *metadata, const char *updatedby, const size_t updatedbylen) {
  int ret = 1;
  if (atclient_atkey_metadata_is_updatedby_initialized(metadata)) {
    atclient_atsign_free(&metadata->updatedby);
  }
  atclient_atsign_init(&metadata->updatedby, updatedby);
  metadata->initializedfields[0] |= ATKEY_METADATA_UPDATEDBY_INITIALIZED;
  ret = 0;
  goto exit;
exit: { return ret; }
}

static int set_status(atclient_atkey_metadata *metadata, const char *status, const size_t statuslen) {
  int ret = 1;
  if (atclient_atkey_metadata_is_status_initialized(metadata)) {
    atclient_atstr_free(&metadata->status);
  }
  if ((ret = atclient_atstr_init_literal(&metadata->status, statuslen + 1, status)) != 0) {
    atclient_atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR,
                          "atclient_atstr_init_literal failed with string \"%.*s\"\n", statuslen, status);
    goto exit;
  }
  metadata->initializedfields[0] |= ATKEY_METADATA_STATUS_INITIALIZED;
  ret = 0;
  goto exit;
exit: { return ret; }
}

static void set_version(atclient_atkey_metadata *metadata, int version) {
  metadata->version = version;
  metadata->initializedfields[0] |= ATKEY_METADATA_VERSION_INITIALIZED;
}

static int set_expiresat(atclient_atkey_metadata *metadata, const char *expiresat, const size_t expiresatlen) {
  int ret = 1;
  if (atclient_atkey_metadata_is_expiresat_initialized(metadata)) {
    atclient_atstr_free(&metadata->expiresat);
  }
  if ((ret = atclient_atstr_init_literal(&metadata->expiresat, expiresatlen + 1, expiresat)) != 0) {
    atclient_atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR,
                          "atclient_atstr_init_literal failed with string \"%.*s\"\n", expiresatlen, expiresat);
    goto exit;
  }
  metadata->initializedfields[0] |= ATKEY_METADATA_EXPIRESAT_INITIALIZED;
  ret = 0;
  goto exit;
exit: { return ret; }
}

static int set_availableat(atclient_atkey_metadata *metadata, const char *availableat, const size_t availableatlen) {
  int ret = 1;
  if (atclient_atkey_metadata_is_availableat_initialized(metadata)) {
    atclient_atstr_free(&metadata->availableat);
  }
  if ((ret = atclient_atstr_init_literal(&metadata->availableat, availableatlen + 1, availableat)) != 0) {
    atclient_atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR,
                          "atclient_atstr_init_literal failed with string \"%.*s\"\n", availableatlen, availableat);
    goto exit;
  }
  metadata->initializedfields[0] |= ATKEY_METADATA_AVAILABLEAT_INITIALIZED;
  ret = 0;
  goto exit;
exit: { return ret; }
}

static int set_refreshat(atclient_atkey_metadata *metadata, const char *refreshat, const size_t refreshatlen) {
  int ret = 1;
  if (atclient_atkey_metadata_is_refreshat_initialized(metadata)) {
    atclient_atstr_free(&metadata->refreshat);
  }
  if ((ret = atclient_atstr_init_literal(&metadata->refreshat, refreshatlen + 1, refreshat)) != 0) {
    atclient_atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR,
                          "atclient_atstr_init_literal failed with string \"%.*s\"\n", refreshatlen, refreshat);
    goto exit;
  }
  metadata->initializedfields[0] |= ATKEY_METADATA_REFRESHAT_INITIALIZED;
  ret = 0;
  goto exit;
exit: { return ret; }
}

static int set_createdat(atclient_atkey_metadata *metadata, const char *createdat, const size_t createdatlen) {
  int ret = 1;
  if (atclient_atkey_metadata_is_createdat_initialized(metadata)) {
    atclient_atstr_free(&metadata->createdat);
  }
  if ((ret = atclient_atstr_init_literal(&metadata->createdat, createdatlen + 1, createdat)) != 0) {
    atclient_atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR,
                          "atclient_atstr_init_literal failed with string \"%.*s\"\n", createdatlen, createdat);
    goto exit;
  }
  metadata->initializedfields[0] |= ATKEY_METADATA_CREATEDAT_INITIALIZED;
  ret = 0;
  goto exit;
exit: { return ret; }
}

static int set_updatedat(atclient_atkey_metadata *metadata, const char *updatedat, const size_t updatedatlen) {
  int ret = 1;
  if (atclient_atkey_metadata_is_updatedat_initialized(metadata)) {
    atclient_atstr_free(&metadata->updatedat);
  }
  if ((ret = atclient_atstr_init_literal(&metadata->updatedat, updatedatlen + 1, updatedat)) != 0) {
    atclient_atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR,
                          "atclient_atstr_init_literal failed with string \"%.*s\"\n", updatedatlen, updatedat);
    goto exit;
  }
  metadata->initializedfields[1] |= ATKEY_METADATA_UPDATEDAT_INITIALIZED;
  ret = 0;
  goto exit;
exit: { return ret; }
}

static void set_ispublic(atclient_atkey_metadata *metadata, const bool ispublic) {
  metadata->ispublic = ispublic;
  metadata->initializedfields[1] |= ATKEY_METADATA_ISPUBLIC_INITIALIZED;
}

static void set_ishidden(atclient_atkey_metadata *metadata, const bool ishidden) {
  metadata->ishidden = ishidden;
  metadata->initializedfields[1] |= ATKEY_METADATA_ISHIDDEN_INITIALIZED;
}

static void set_iscached(atclient_atkey_metadata *metadata, const bool iscached) {
  metadata->iscached = iscached;
  metadata->initializedfields[1] |= ATKEY_METADATA_ISCACHED_INITIALIZED;
}

static void set_ttl(atclient_atkey_metadata *metadata, const long ttl) {
  metadata->ttl = ttl;
  metadata->initializedfields[1] |= ATKEY_METADATA_TTL_INITIALIZED;
}

static void set_ttb(atclient_atkey_metadata *metadata, const long ttb) {
  metadata->ttb = ttb;
  metadata->initializedfields[1] |= ATKEY_METADATA_TTB_INITIALIZED;
}

static void set_ttr(atclient_atkey_metadata *metadata, const long ttr) {
  metadata->ttr = ttr;
  metadata->initializedfields[1] |= ATKEY_METADATA_TTR_INITIALIZED;
}

static void set_ccd(atclient_atkey_metadata *metadata, const bool ccd) {
  metadata->ccd = ccd;
  metadata->initializedfields[1] |= ATKEY_METADATA_CCD_INITIALIZED;
}

static void set_isbinary(atclient_atkey_metadata *metadata, const bool isbinary) {
  metadata->isbinary = isbinary;
  metadata->initializedfields[2] |= ATKEY_METADATA_ISBINARY_INITIALIZED;
}

static void set_isencrypted(atclient_atkey_metadata *metadata, const bool isencrypted) {
  metadata->isencrypted = isencrypted;
  metadata->initializedfields[2] |= ATKEY_METADATA_ISENCRYPTED_INITIALIZED;
}

static int set_datasignature(atclient_atkey_metadata *metadata, const char *datasignature,
                             const size_t datasignaturelen) {
  int ret = 1;
  if (atclient_atkey_metadata_is_datasignature_initialized(metadata)) {
    atclient_atstr_free(&metadata->datasignature);
  }
  if ((ret = atclient_atstr_init_literal(&metadata->datasignature, datasignaturelen + 1, datasignature)) != 0) {
    atclient_atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR,
                          "atclient_atstr_init_literal failed with string \"%.*s\"\n", datasignaturelen, datasignature);
    goto exit;
  }
  metadata->initializedfields[2] |= ATKEY_METADATA_DATASIGNATURE_INITIALIZED;
  ret = 0;
  goto exit;
exit: { return ret; }
}

static int set_sharedkeystatus(atclient_atkey_metadata *metadata, const char *sharedkeystatus,
                               const size_t sharedkeystatuslen) {
  int ret = 1;
  if (atclient_atkey_metadata_is_sharedkeystatus_initialized(metadata)) {
    atclient_atstr_free(&metadata->sharedkeystatus);
  }
  if ((ret = atclient_atstr_init_literal(&metadata->sharedkeystatus, sharedkeystatuslen + 1, sharedkeystatus)) != 0) {
    atclient_atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR,
                          "atclient_atstr_init_literal failed with string \"%.*s\"\n", sharedkeystatuslen,
                          sharedkeystatus);
    goto exit;
  }
  metadata->initializedfields[2] |= ATKEY_METADATA_SHAREDKEYSTATUS_INITIALIZED;
  ret = 0;
  goto exit;
exit: { return ret; }
}

static int set_sharedkeyenc(atclient_atkey_metadata *metadata, const char *sharedkeyenc, const size_t sharedkeyenclen) {
  int ret = 1;
  if (atclient_atkey_metadata_is_sharedkeyenc_initialized(metadata)) {
    atclient_atstr_free(&metadata->sharedkeyenc);
  }
  if ((ret = atclient_atstr_init_literal(&metadata->sharedkeyenc, sharedkeyenclen + 1, sharedkeyenc)) != 0) {
    atclient_atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR,
                          "atclient_atstr_init_literal failed with string \"%.*s\"\n", sharedkeyenclen + 1,
                          sharedkeyenc);
    goto exit;
  }
  metadata->initializedfields[2] |= ATKEY_METADATA_SHAREDKEYENC_INITIALIZED;
  ret = 0;
  goto exit;
exit: { return ret; }
}

static int set_pubkeyhash(atclient_atkey_metadata *metadata, const char *pubkeyhash, const size_t pubkeyhashlen) {
  int ret = 1;
  if (atclient_atkey_metadata_is_pubkeyhash_initialized(metadata)) {
    atclient_atstr_free(&metadata->pubkeyhash);
  }
  if ((ret = atclient_atstr_init_literal(&metadata->pubkeyhash, pubkeyhashlen + 1, pubkeyhash)) != 0) {
    atclient_atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR,
                          "atclient_atstr_init_literal failed with string \"%.*s\"\n", pubkeyhashlen, pubkeyhash);
    goto exit;
  }
  metadata->initializedfields[2] |= ATKEY_METADATA_PUBKEYHASH_INITIALIZED;
  ret = 0;
  goto exit;
exit: { return ret; }
}

static int set_pubkeyalgo(atclient_atkey_metadata *metadata, const char *pubkeyalgo, const size_t pubkeyalgolen) {
  int ret = 1;
  if (atclient_atkey_metadata_is_pubkeyalgo_initialized(metadata)) {
    atclient_atstr_free(&metadata->pubkeyalgo);
  }
  if ((ret = atclient_atstr_init_literal(&metadata->pubkeyalgo, pubkeyalgolen + 1, pubkeyalgo)) != 0) {
    atclient_atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR,
                          "atclient_atstr_init_literal failed with string \"%.*s\"\n", pubkeyalgolen, pubkeyalgo);
    goto exit;
  }
  metadata->initializedfields[2] |= ATKEY_METADATA_PUBKEYALGO_INITIALIZED;
  ret = 0;
  goto exit;
exit: { return ret; }
}

static int set_encoding(atclient_atkey_metadata *metadata, const char *encoding, const size_t encodinglen) {
  int ret = 1;
  if (atclient_atkey_metadata_is_encoding_initialized(metadata)) {
    atclient_atstr_free(&metadata->encoding);
  }
  if ((ret = atclient_atstr_init_literal(&metadata->encoding, encodinglen + 1, encoding)) != 0) {
    atclient_atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR,
                          "atclient_atstr_init_literal failed with string \"%.*s\"\n", encodinglen, encoding);
    goto exit;
  }
  metadata->initializedfields[2] |= ATKEY_METADATA_ENCODING_INITIALIZED;
  ret = 0;
  goto exit;
exit: { return ret; }
}

static int set_enckeyname(atclient_atkey_metadata *metadata, const char *enckeyname, const size_t enckeynamelen) {
  int ret = 1;
  if (atclient_atkey_metadata_is_enckeyname_initialized(metadata)) {
    atclient_atstr_free(&metadata->enckeyname);
  }
  if ((ret = atclient_atstr_init_literal(&metadata->enckeyname, enckeynamelen + 1, enckeyname)) != 0) {
    atclient_atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR,
                          "atclient_atstr_init_literal failed with string \"%.*s\"\n", enckeynamelen, enckeyname);
    goto exit;
  }
  metadata->initializedfields[3] |= ATKEY_METADATA_ENCKEYNAME_INITIALIZED;
  ret = 0;
  goto exit;
exit: { return ret; }
}

static int set_encalgo(atclient_atkey_metadata *metadata, const char *encalgo, const size_t encalgolen) {
  int ret = 1;
  if (atclient_atkey_metadata_is_encalgo_initialized(metadata)) {
    atclient_atstr_free(&metadata->encalgo);
  }
  if ((ret = atclient_atstr_init_literal(&metadata->encalgo, encalgolen + 1, encalgo)) != 0) {
    atclient_atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR,
                          "atclient_atstr_init_literal failed with string \"%.*s\"\n", encalgolen, encalgo);
    goto exit;
  }
  metadata->initializedfields[3] |= ATKEY_METADATA_ENCALGO_INITIALIZED;
  ret = 0;
  goto exit;
exit: { return ret; }
}

static int set_ivnonce(atclient_atkey_metadata *metadata, const char *ivnonce, const size_t ivnoncelen) {
  int ret = 1;
  if (atclient_atkey_metadata_is_ivnonce_initialized(metadata)) {
    atclient_atstr_free(&metadata->ivnonce);
  }
  if ((ret = atclient_atstr_init_literal(&metadata->ivnonce, ivnoncelen + 1, ivnonce)) != 0) {
    atclient_atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR,
                          "atclient_atstr_init_literal failed with string \"%.*s\"\n", ivnoncelen, ivnonce);
    goto exit;
  }
  metadata->initializedfields[3] |= ATKEY_METADATA_IVNONCE_INITIALIZED;
  ret = 0;
  goto exit;
exit: { return ret; }
}

static int set_skeenckeyname(atclient_atkey_metadata *metadata, const char *skeenckeyname,
                             const size_t skeenckeynamelen) {
  int ret = 1;
  if (atclient_atkey_metadata_is_skeenckeyname_initialized(metadata)) {
    atclient_atstr_free(&metadata->skeenckeyname);
  }
  if ((ret = atclient_atstr_init_literal(&metadata->skeenckeyname, skeenckeynamelen + 1, skeenckeyname)) != 0) {
    atclient_atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR,
                          "atclient_atstr_init_literal failed with string \"%.*s\"\n", skeenckeynamelen, skeenckeyname);
    goto exit;
  }
  metadata->initializedfields[3] |= ATKEY_METADATA_SKEENCKEYNAME_INITIALIZED;
  ret = 0;
  goto exit;
exit: { return ret; }
}

static int set_skeencalgo(atclient_atkey_metadata *metadata, const char *skeencalgo, const size_t skeencalgolen) {
  int ret = 1;
  if (atclient_atkey_metadata_is_skeencalgo_initialized(metadata)) {
    atclient_atstr_free(&metadata->skeencalgo);
  }
  if ((ret = atclient_atstr_init_literal(&metadata->skeencalgo, skeencalgolen + 1, skeencalgo)) != 0) {
    atclient_atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR,
                          "atclient_atstr_init_literal failed with string \"%.*s\"\n", skeencalgolen, skeencalgo);
    goto exit;
  }
  metadata->initializedfields[3] |= ATKEY_METADATA_SKEENCALGO_INITIALIZED;
  ret = 0;
  goto exit;
exit: { return ret; }
}

void atclient_atkey_metadata_init(atclient_atkey_metadata *metadata) {
  memset(metadata, 0, sizeof(atclient_atkey_metadata));
}

int atclient_atkey_metadata_from_jsonstr(atclient_atkey_metadata *metadata, const char *metadatastr,
                                         const unsigned long metadatastrlen) {
  int ret = 1;

  cJSON *root = cJSON_Parse(metadatastr);
  if (root == NULL) {
    atclient_atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "cJSON_Parse failed\n");
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
    set_createdby(metadata, createdby->valuestring, strlen(createdby->valuestring));
  }

  cJSON *updatedby = cJSON_GetObjectItem(json, "updatedBy");
  if (updatedby != NULL) {
    set_updatedby(metadata, updatedby->valuestring, strlen(updatedby->valuestring));
  }

  cJSON *status = cJSON_GetObjectItem(json, "status");
  if (status != NULL) {
    set_status(metadata, status->valuestring, strlen(status->valuestring));
  }

  cJSON *version = cJSON_GetObjectItem(json, "version");
  if (version != NULL) {
    set_version(metadata, version->valueint);
  }

  cJSON *expiresat = cJSON_GetObjectItem(json, "expiresAt");
  if (expiresat != NULL) {
    set_expiresat(metadata, expiresat->valuestring, strlen(expiresat->valuestring));
  }

  cJSON *availableat = cJSON_GetObjectItem(json, "availableAt");
  if (availableat != NULL) {
    set_availableat(metadata, availableat->valuestring, strlen(availableat->valuestring));
  }

  cJSON *refreshat = cJSON_GetObjectItem(json, "refreshAt");
  if (refreshat != NULL) {
    set_refreshat(metadata, refreshat->valuestring, strlen(refreshat->valuestring));
  }

  cJSON *createdat = cJSON_GetObjectItem(json, "createdAt");
  if (createdat != NULL) {
    set_createdat(metadata, createdat->valuestring, strlen(createdat->valuestring));
  }

  cJSON *updatedat = cJSON_GetObjectItem(json, "updatedAt");
  if (updatedat != NULL) {
    set_updatedat(metadata, updatedat->valuestring, strlen(updatedat->valuestring));
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
    set_ttl(metadata, ttl->valueint);
  }

  cJSON *ttb = cJSON_GetObjectItem(json, "ttb");
  if (ttb != NULL) {
    set_ttb(metadata, ttb->valueint);
  }

  cJSON *ttr = cJSON_GetObjectItem(json, "ttr");
  if (ttr != NULL) {
    set_ttr(metadata, ttr->valueint);
  }

  cJSON *ccd = cJSON_GetObjectItem(json, "ccd");
  if (ccd != NULL) {
    set_ccd(metadata, ccd->valueint);
  }

  cJSON *isbinary = cJSON_GetObjectItem(json, "isBinary");
  if (isbinary != NULL) {
    set_isbinary(metadata, isbinary->valueint);
  }

  cJSON *isencrypted = cJSON_GetObjectItem(json, "isEncrypted");
  if (isencrypted != NULL) {
    set_isencrypted(metadata, isencrypted->valueint);
  }

  cJSON *datasignature = cJSON_GetObjectItem(json, "dataSignature");
  if (datasignature != NULL) {
    set_datasignature(metadata, datasignature->valuestring, strlen(datasignature->valuestring));
  }

  cJSON *sharedkeystatus = cJSON_GetObjectItem(json, "sharedKeyStatus");
  if (sharedkeystatus != NULL) {
    set_sharedkeystatus(metadata, sharedkeystatus->valuestring, strlen(sharedkeystatus->valuestring));
  }

  cJSON *sharedkeyenc = cJSON_GetObjectItem(json, "sharedKeyEnc");
  if (sharedkeyenc != NULL) {
    set_sharedkeyenc(metadata, sharedkeyenc->valuestring, strlen(sharedkeyenc->valuestring));
  }

  cJSON *pubkeyhash = cJSON_GetObjectItem(json, "pubKeyHash");
  if (pubkeyhash != NULL) {
    set_pubkeyhash(metadata, pubkeyhash->valuestring, strlen(pubkeyhash->valuestring));
  }

  cJSON *pubkeyalgo = cJSON_GetObjectItem(json, "pubKeyAlgo");
  if (pubkeyalgo != NULL) {
    set_pubkeyalgo(metadata, pubkeyalgo->valuestring, strlen(pubkeyalgo->valuestring));
  }

  cJSON *encoding = cJSON_GetObjectItem(json, "encoding");
  if (encoding != NULL) {
    set_encoding(metadata, encoding->valuestring, strlen(encoding->valuestring));
  }

  cJSON *enckeyname = cJSON_GetObjectItem(json, "encKeyName");
  if (enckeyname != NULL) {
    set_enckeyname(metadata, enckeyname->valuestring, strlen(enckeyname->valuestring));
  }

  cJSON *encalgo = cJSON_GetObjectItem(json, "encAlgo");
  if (encalgo != NULL) {
    set_encalgo(metadata, encalgo->valuestring, strlen(encalgo->valuestring));
  }

  cJSON *ivnonce = cJSON_GetObjectItem(json, "ivNonce");
  if (ivnonce != NULL) {
    set_ivnonce(metadata, ivnonce->valuestring, strlen(ivnonce->valuestring));
  }

  cJSON *skeenckeyname = cJSON_GetObjectItem(json, "skeEncKeyName");
  if (skeenckeyname != NULL) {
    set_skeenckeyname(metadata, skeenckeyname->valuestring, strlen(skeenckeyname->valuestring));
  }

  cJSON *skeencalgo = cJSON_GetObjectItem(json, "skeEncAlgo");
  if (skeencalgo != NULL) {
    set_skeencalgo(metadata, skeencalgo->valuestring, strlen(skeencalgo->valuestring));
  }
}

int atclient_atkey_metadata_to_jsonstr(const atclient_atkey_metadata *metadata, char *metadatastr,
                                       const unsigned long metadatastrlen, unsigned long *metadatastrolen) {
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
    atclient_atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "cJSON_Print failed\n");
    goto exit;
  }

  if (strlen(jsonstr) > metadatastrlen) {
    atclient_atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "metadatastr buffer too small: %lu > %lu\n",
                          strlen(jsonstr), metadatastrlen);
    free(jsonstr);
    goto exit;
  }

  strcpy(metadatastr, jsonstr);
  *metadatastrolen = strlen(jsonstr);
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
    len += 5 // :ttl:
           + long_strlen(metadata->ttl);
  }
  return len;
}

int atclient_atkey_metadata_to_protocol_str(const atclient_atkey_metadata *metadata, char *metadatastr,
                                            const size_t metadatastrlen, size_t *metadatastrolen) {
  int ret = 1;

  atclient_atstr protocolstr;
  atclient_atstr_init(&protocolstr, 4096);

  if (atclient_atkey_metadata_is_ttl_initialized(metadata)) {
    if ((ret = atclient_atstr_append(&protocolstr, ":ttl:%ld", metadata->ttl) != 0)) {
      atclient_atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atclient_atstr_append failed\n");
      goto exit;
    }
  }

  if (atclient_atkey_metadata_is_ttb_initialized(metadata)) {
    if ((ret = atclient_atstr_append(&protocolstr, ":ttb:%ld", metadata->ttb) != 0)) {
      atclient_atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atclient_atstr_append failed\n");
      goto exit;
    }
  }

  if (atclient_atkey_metadata_is_ttr_initialized(metadata)) {
    if ((ret = atclient_atstr_append(&protocolstr, ":ttr:%ld", metadata->ttr) != 0)) {
      atclient_atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atclient_atstr_append failed\n");
      goto exit;
    }
  }

  if (atclient_atkey_metadata_is_ccd_initialized(metadata) && metadata->ccd) {
    if ((ret = atclient_atstr_append(&protocolstr, ":ccd:true") != 0)) {
      atclient_atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atclient_atstr_append failed\n");
      goto exit;
    }
  }

  if (atclient_atkey_metadata_is_isbinary_initialized(metadata) && metadata->isbinary) {
    if ((ret = atclient_atstr_append(&protocolstr, ":isBinary:true") != 0)) {
      atclient_atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atclient_atstr_append failed\n");
      goto exit;
    }
  }

  if (atclient_atkey_metadata_is_isencrypted_initialized(metadata) && metadata->isencrypted) {
    if ((ret = atclient_atstr_append(&protocolstr, ":isEncrypted:true") != 0)) {
      atclient_atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atclient_atstr_append failed\n");
      goto exit;
    }
  }

  if (atclient_atkey_metadata_is_datasignature_initialized(metadata)) {
    if ((ret = atclient_atstr_append(&protocolstr, ":dataSignature:%s", metadata->datasignature.str) != 0)) {
      atclient_atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atclient_atstr_append failed\n");
      goto exit;
    }
  }

  if (atclient_atkey_metadata_is_sharedkeystatus_initialized(metadata)) {
    if ((ret = atclient_atstr_append(&protocolstr, ":sharedKeyStatus:%s", metadata->sharedkeystatus.str) != 0)) {
      atclient_atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atclient_atstr_append failed\n");
      goto exit;
    }
  }

  if (atclient_atkey_metadata_is_sharedkeyenc_initialized(metadata)) {
    if ((ret = atclient_atstr_append(&protocolstr, ":sharedKeyEnc:%s", metadata->sharedkeyenc.str) != 0)) {
      atclient_atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atclient_atstr_append failed\n");
      goto exit;
    }
  }

  if (atclient_atkey_metadata_is_pubkeyhash_initialized(metadata)) {
    if ((ret = atclient_atstr_append(&protocolstr, ":hash:%s", metadata->pubkeyhash.str) != 0)) {
      atclient_atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atclient_atstr_append failed\n");
      goto exit;
    }
  }

  if (atclient_atkey_metadata_is_pubkeyalgo_initialized(metadata)) {
    if ((ret = atclient_atstr_append(&protocolstr, ":algo:%s", metadata->pubkeyalgo.str) != 0)) {
      atclient_atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atclient_atstr_append failed\n");
      goto exit;
    }
  }

  if (atclient_atkey_metadata_is_encoding_initialized(metadata)) {
    if ((ret = atclient_atstr_append(&protocolstr, ":encoding:%s", metadata->encoding.str) != 0)) {
      atclient_atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atclient_atstr_append failed\n");
      goto exit;
    }
  }

  if (atclient_atkey_metadata_is_enckeyname_initialized(metadata)) {
    if ((ret = atclient_atstr_append(&protocolstr, ":encKeyName:%s", metadata->enckeyname.str) != 0)) {
      atclient_atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atclient_atstr_append failed\n");
      goto exit;
    }
  }

  if (atclient_atkey_metadata_is_encalgo_initialized(metadata)) {
    if ((ret = atclient_atstr_append(&protocolstr, ":encAlgo:%s", metadata->encalgo.str) != 0)) {
      atclient_atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atclient_atstr_append failed\n");
      goto exit;
    }
  }

  if (atclient_atkey_metadata_is_ivnonce_initialized(metadata)) {
    if ((ret = atclient_atstr_append(&protocolstr, ":ivNonce:%s", metadata->ivnonce.str) != 0)) {
      atclient_atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atclient_atstr_append failed\n");
      goto exit;
    }
  }

  if (atclient_atkey_metadata_is_skeenckeyname_initialized(metadata)) {
    if ((ret = atclient_atstr_append(&protocolstr, ":skeEncKeyName:%s", metadata->skeenckeyname.str) != 0)) {
      atclient_atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atclient_atstr_append failed\n");
      goto exit;
    }
  }

  if (atclient_atkey_metadata_is_skeencalgo_initialized(metadata)) {
    if ((ret = atclient_atstr_append(&protocolstr, ":skeEncAlgo:%s", metadata->skeencalgo.str) != 0)) {
      atclient_atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atclient_atstr_append failed\n");
      goto exit;
    }
  }

  if (protocolstr.olen > metadatastrlen) {
    atclient_atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "metadatastr buffer too small\n");
    goto exit;
  }

  strcpy(metadatastr, protocolstr.str);
  *metadatastrolen = protocolstr.olen;

  ret = 0;
  goto exit;

exit: {
  atclient_atstr_free(&protocolstr);
  return ret;
}
}

bool atclient_atkey_metadata_is_createdby_initialized(const atclient_atkey_metadata *metadata) {
  return metadata->initializedfields[0] & ATKEY_METADATA_CREATEDBY_INITIALIZED;
}

bool atclient_atkey_metadata_is_updatedby_initialized(const atclient_atkey_metadata *metadata) {
  return metadata->initializedfields[0] & ATKEY_METADATA_UPDATEDBY_INITIALIZED;
}

bool atclient_atkey_metadata_is_status_initialized(const atclient_atkey_metadata *metadata) {
  return metadata->initializedfields[0] & ATKEY_METADATA_STATUS_INITIALIZED;
}

bool atclient_atkey_metadata_is_version_initialized(const atclient_atkey_metadata *metadata) {
  return metadata->initializedfields[0] & ATKEY_METADATA_VERSION_INITIALIZED;
}

bool atclient_atkey_metadata_is_availableat_initialized(const atclient_atkey_metadata *metadata) {
  return metadata->initializedfields[0] & ATKEY_METADATA_AVAILABLEAT_INITIALIZED;
}

bool atclient_atkey_metadata_is_expiresat_initialized(const atclient_atkey_metadata *metadata) {
  return metadata->initializedfields[0] & ATKEY_METADATA_EXPIRESAT_INITIALIZED;
}

bool atclient_atkey_metadata_is_refreshat_initialized(const atclient_atkey_metadata *metadata) {
  return metadata->initializedfields[0] & ATKEY_METADATA_REFRESHAT_INITIALIZED;
}

bool atclient_atkey_metadata_is_createdat_initialized(const atclient_atkey_metadata *metadata) {
  return metadata->initializedfields[0] & ATKEY_METADATA_CREATEDAT_INITIALIZED;
}

bool atclient_atkey_metadata_is_updatedat_initialized(const atclient_atkey_metadata *metadata) {
  return metadata->initializedfields[1] & ATKEY_METADATA_UPDATEDAT_INITIALIZED;
}

bool atclient_atkey_metadata_is_ispublic_initialized(const atclient_atkey_metadata *metadata) {
  return metadata->initializedfields[1] & ATKEY_METADATA_ISPUBLIC_INITIALIZED;
}

bool atclient_atkey_metadata_is_ishidden_initialized(const atclient_atkey_metadata *metadata) {
  return metadata->initializedfields[1] & ATKEY_METADATA_ISHIDDEN_INITIALIZED;
}

bool atclient_atkey_metadata_is_iscached_initialized(const atclient_atkey_metadata *metadata) {
  return metadata->initializedfields[1] & ATKEY_METADATA_ISCACHED_INITIALIZED;
}

bool atclient_atkey_metadata_is_ttl_initialized(const atclient_atkey_metadata *metadata) {
  return metadata->initializedfields[1] & ATKEY_METADATA_TTL_INITIALIZED;
}

bool atclient_atkey_metadata_is_ttb_initialized(const atclient_atkey_metadata *metadata) {
  return metadata->initializedfields[1] & ATKEY_METADATA_TTB_INITIALIZED;
}

bool atclient_atkey_metadata_is_ttr_initialized(const atclient_atkey_metadata *metadata) {
  return metadata->initializedfields[1] & ATKEY_METADATA_TTR_INITIALIZED;
}

bool atclient_atkey_metadata_is_ccd_initialized(const atclient_atkey_metadata *metadata) {
  return metadata->initializedfields[1] & ATKEY_METADATA_CCD_INITIALIZED;
}

bool atclient_atkey_metadata_is_isbinary_initialized(const atclient_atkey_metadata *metadata) {
  return metadata->initializedfields[2] & ATKEY_METADATA_ISBINARY_INITIALIZED;
}

bool atclient_atkey_metadata_is_isencrypted_initialized(const atclient_atkey_metadata *metadata) {
  return metadata->initializedfields[2] & ATKEY_METADATA_ISENCRYPTED_INITIALIZED;
}

bool atclient_atkey_metadata_is_datasignature_initialized(const atclient_atkey_metadata *metadata) {
  return metadata->initializedfields[2] & ATKEY_METADATA_DATASIGNATURE_INITIALIZED;
}

bool atclient_atkey_metadata_is_sharedkeystatus_initialized(const atclient_atkey_metadata *metadata) {
  return metadata->initializedfields[2] & ATKEY_METADATA_SHAREDKEYSTATUS_INITIALIZED;
}

bool atclient_atkey_metadata_is_sharedkeyenc_initialized(const atclient_atkey_metadata *metadata) {
  return metadata->initializedfields[2] & ATKEY_METADATA_SHAREDKEYENC_INITIALIZED;
}

bool atclient_atkey_metadata_is_pubkeyhash_initialized(const atclient_atkey_metadata *metadata) {
  return metadata->initializedfields[2] & ATKEY_METADATA_PUBKEYHASH_INITIALIZED;
}

bool atclient_atkey_metadata_is_pubkeyalgo_initialized(const atclient_atkey_metadata *metadata) {
  return metadata->initializedfields[2] & ATKEY_METADATA_PUBKEYALGO_INITIALIZED;
}

bool atclient_atkey_metadata_is_encoding_initialized(const atclient_atkey_metadata *metadata) {
  return metadata->initializedfields[2] & ATKEY_METADATA_ENCODING_INITIALIZED;
}

bool atclient_atkey_metadata_is_enckeyname_initialized(const atclient_atkey_metadata *metadata) {
  return metadata->initializedfields[3] & ATKEY_METADATA_ENCKEYNAME_INITIALIZED;
}

bool atclient_atkey_metadata_is_encalgo_initialized(const atclient_atkey_metadata *metadata) {
  return metadata->initializedfields[3] & ATKEY_METADATA_ENCALGO_INITIALIZED;
}

bool atclient_atkey_metadata_is_ivnonce_initialized(const atclient_atkey_metadata *metadata) {
  return metadata->initializedfields[3] & ATKEY_METADATA_IVNONCE_INITIALIZED;
}

bool atclient_atkey_metadata_is_skeenckeyname_initialized(const atclient_atkey_metadata *metadata) {
  return metadata->initializedfields[3] & ATKEY_METADATA_SKEENCKEYNAME_INITIALIZED;
}

bool atclient_atkey_metadata_is_skeencalgo_initialized(const atclient_atkey_metadata *metadata) {
  return metadata->initializedfields[3] & ATKEY_METADATA_SKEENCALGO_INITIALIZED;
}

void atclient_atkey_metadata_set_ispublic(atclient_atkey_metadata *metadata, const bool ispublic) {
  set_ispublic(metadata, ispublic);
}

void atclient_atkey_metadata_set_ishidden(atclient_atkey_metadata *metadata, const bool ishidden) {
  set_ishidden(metadata, ishidden);
}

void atclient_atkey_metadata_set_iscached(atclient_atkey_metadata *metadata, const bool iscached) {
  set_iscached(metadata, iscached);
}

void atclient_atkey_metadata_set_ttl(atclient_atkey_metadata *metadata, const long ttl) { set_ttl(metadata, ttl); }

void atclient_atkey_metadata_set_ttb(atclient_atkey_metadata *metadata, const long ttb) { set_ttb(metadata, ttb); }

void atclient_atkey_metadata_set_ttr(atclient_atkey_metadata *metadata, const long ttr) { set_ttr(metadata, ttr); }

void atclient_atkey_metadata_set_isbinary(atclient_atkey_metadata *metadata, const bool isbinary) {
  set_isbinary(metadata, isbinary);
}

void atclient_atkey_metadata_set_isencrypted(atclient_atkey_metadata *metadata, const bool isencrypted) {
  set_isencrypted(metadata, isencrypted);
}

int atclient_atkey_metadata_set_datasignature(atclient_atkey_metadata *metadata, const char *datasignature,
                                              const size_t datasignaturelen) {
  return set_datasignature(metadata, datasignature, datasignaturelen);
}

int atclient_atkey_metadata_set_sharedkeystatus(atclient_atkey_metadata *metadata, const char *sharedkeystatus,
                                                const size_t sharedkeystatuslen) {
  return set_sharedkeystatus(metadata, sharedkeystatus, sharedkeystatuslen);
}

int atclient_atkey_metadata_set_sharedkeyenc(atclient_atkey_metadata *metadata, const char *sharedkeyenc,
                                             const size_t sharedkeyenclen) {
  return set_sharedkeyenc(metadata, sharedkeyenc, sharedkeyenclen);
}

int atclient_atkey_metadata_set_pubkeyhash(atclient_atkey_metadata *metadata, const char *pubkeyhash,
                                           const size_t pubkeyhashlen) {
  return set_pubkeyhash(metadata, pubkeyhash, pubkeyhashlen);
}

int atclient_atkey_metadata_set_pubkeyalgo(atclient_atkey_metadata *metadata, const char *pubkeyalgo,
                                           const size_t pubkeyalgolen) {
  return set_pubkeyalgo(metadata, pubkeyalgo, pubkeyalgolen);
}

int atclient_atkey_metadata_set_encoding(atclient_atkey_metadata *metadata, const char *encoding,
                                         const size_t encodinglen) {
  return set_encoding(metadata, encoding, encodinglen);
}

int atclient_atkey_metadata_set_enckeyname(atclient_atkey_metadata *metadata, const char *enckeyname,
                                           const size_t enckeynamelen) {
  return set_enckeyname(metadata, enckeyname, enckeynamelen);
}

int atclient_atkey_metadata_set_encalgo(atclient_atkey_metadata *metadata, const char *encalgo,
                                        const size_t encalgolen) {
  return set_encalgo(metadata, encalgo, encalgolen);
}

int atclient_atkey_metadata_set_ivnonce(atclient_atkey_metadata *metadata, const char *ivnonce,
                                        const size_t ivnoncelen) {
  return set_ivnonce(metadata, ivnonce, ivnoncelen);
}

int atclient_atkey_metadata_set_skeenckeyname(atclient_atkey_metadata *metadata, const char *skeenckeyname,
                                              const size_t skeenckeynamelen) {
  return set_skeenckeyname(metadata, skeenckeyname, skeenckeynamelen);
}

int atclient_atkey_metadata_set_skeencalgo(atclient_atkey_metadata *metadata, const char *skeencalgo,
                                           const size_t skeencalgolen) {
  return set_skeencalgo(metadata, skeencalgo, skeencalgolen);
}

void atclient_atkey_metadata_free(atclient_atkey_metadata *metadata) {
  if (atclient_atkey_metadata_is_createdby_initialized(metadata)) {
    atclient_atsign_free(&metadata->createdby);
    metadata->initializedfields[0] &= ~ATKEY_METADATA_CREATEDBY_INITIALIZED;
  }

  if (atclient_atkey_metadata_is_updatedby_initialized(metadata)) {
    atclient_atsign_free(&metadata->updatedby);
    metadata->initializedfields[0] &= ~ATKEY_METADATA_UPDATEDBY_INITIALIZED;
  }

  if (atclient_atkey_metadata_is_status_initialized(metadata)) {
    atclient_atstr_free(&metadata->status);
    metadata->initializedfields[0] &= ~ATKEY_METADATA_STATUS_INITIALIZED;
  }

  if (atclient_atkey_metadata_is_availableat_initialized(metadata)) {
    atclient_atstr_free(&metadata->availableat);
    metadata->initializedfields[0] &= ~ATKEY_METADATA_AVAILABLEAT_INITIALIZED;
  }

  if (atclient_atkey_metadata_is_expiresat_initialized(metadata)) {
    atclient_atstr_free(&metadata->expiresat);
    metadata->initializedfields[0] &= ~ATKEY_METADATA_EXPIRESAT_INITIALIZED;
  }

  if (atclient_atkey_metadata_is_refreshat_initialized(metadata)) {
    atclient_atstr_free(&metadata->refreshat);
    metadata->initializedfields[0] &= ~ATKEY_METADATA_REFRESHAT_INITIALIZED;
  }

  if (atclient_atkey_metadata_is_createdat_initialized(metadata)) {
    atclient_atstr_free(&metadata->createdat);
    metadata->initializedfields[0] &= ~ATKEY_METADATA_CREATEDAT_INITIALIZED;
  }

  if (atclient_atkey_metadata_is_updatedat_initialized(metadata)) {
    atclient_atstr_free(&metadata->updatedat);
    metadata->initializedfields[1] &= ~ATKEY_METADATA_UPDATEDAT_INITIALIZED;
  }

  if (atclient_atkey_metadata_is_datasignature_initialized(metadata)) {
    atclient_atstr_free(&metadata->datasignature);
    metadata->initializedfields[2] &= ~ATKEY_METADATA_DATASIGNATURE_INITIALIZED;
  }

  if (atclient_atkey_metadata_is_sharedkeystatus_initialized(metadata)) {
    atclient_atstr_free(&metadata->sharedkeystatus);
    metadata->initializedfields[2] &= ~ATKEY_METADATA_SHAREDKEYSTATUS_INITIALIZED;
  }

  if (atclient_atkey_metadata_is_sharedkeyenc_initialized(metadata)) {
    atclient_atstr_free(&metadata->sharedkeyenc);
    metadata->initializedfields[2] &= ~ATKEY_METADATA_SHAREDKEYENC_INITIALIZED;
  }

  if (atclient_atkey_metadata_is_pubkeyhash_initialized(metadata)) {
    atclient_atstr_free(&metadata->pubkeyhash);
    metadata->initializedfields[2] &= ~ATKEY_METADATA_PUBKEYHASH_INITIALIZED;
  }

  if (atclient_atkey_metadata_is_pubkeyalgo_initialized(metadata)) {
    atclient_atstr_free(&metadata->pubkeyalgo);
    metadata->initializedfields[2] &= ~ATKEY_METADATA_PUBKEYALGO_INITIALIZED;
  }

  if (atclient_atkey_metadata_is_encoding_initialized(metadata)) {
    atclient_atstr_free(&metadata->encoding);
    metadata->initializedfields[2] &= ~ATKEY_METADATA_ENCODING_INITIALIZED;
  }

  if (atclient_atkey_metadata_is_enckeyname_initialized(metadata)) {
    atclient_atstr_free(&metadata->enckeyname);
    metadata->initializedfields[2] &= ~ATKEY_METADATA_ENCKEYNAME_INITIALIZED;
  }

  if (atclient_atkey_metadata_is_encalgo_initialized(metadata)) {
    atclient_atstr_free(&metadata->encalgo);
    metadata->initializedfields[2] &= ~ATKEY_METADATA_ENCALGO_INITIALIZED;
  }

  if (atclient_atkey_metadata_is_ivnonce_initialized(metadata)) {
    atclient_atstr_free(&metadata->ivnonce);
    metadata->initializedfields[3] &= ~ATKEY_METADATA_IVNONCE_INITIALIZED;
  }

  if (atclient_atkey_metadata_is_skeenckeyname_initialized(metadata)) {
    atclient_atstr_free(&metadata->skeenckeyname);
    metadata->initializedfields[3] &= ~ATKEY_METADATA_SKEENCKEYNAME_INITIALIZED;
  }

  if (atclient_atkey_metadata_is_skeencalgo_initialized(metadata)) {
    atclient_atstr_free(&metadata->skeencalgo);
    metadata->initializedfields[3] &= ~ATKEY_METADATA_SKEENCALGO_INITIALIZED;
  }
}
