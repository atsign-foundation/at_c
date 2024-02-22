#include "atclient/metadata.h"
#include "atclient/atsign.h"
#include "atclient/atstr.h"
#include "atlogger/atlogger.h"
#include "cJSON/cJSON.h"
#include <stdlib.h>
#include <string.h>

#define TAG "metadata"

void atclient_atkey_metadata_init(atclient_atkey_metadata *metadata) {
  memset(metadata, 0, sizeof(atclient_atkey_metadata));
}

int atclient_atkey_metadata_from_jsonstr(atclient_atkey_metadata *metadata, const char *metadatastr,
                                         const unsigned long metadatastrlen) {
  int ret = 1;

  ret = 0;
  goto exit;

exit: { return ret; }
}

int atclient_atkey_metadata_to_jsonstr(const atclient_atkey_metadata metadata, char *metadatastr,
                                       const unsigned long metadatastrlen, unsigned long *metadatastrolen) {
  int ret = 1;

  ret = 0;
  goto exit;
exit: { return ret; }
}

int atclient_atkey_metadata_to_protocolstr(const atclient_atkey_metadata metadata, char *metadatastr,
                                           const size_t metadatastrlen, size_t *metadatastrolen) {
  int ret = 1;

  ret = 0;
  goto exit;

exit: { return ret; }
}

static int set_createdby(atclient_atkey_metadata *metadata, const char *createdby, const size_t createdbylen) {
  int ret = 1;
  if(atclient_atkey_metadata_is_createdby_initialized(*metadata)) {
    atclient_atsign_free(&metadata->createdby);
  }
  atclient_atsign_init(&metadata->createdby, createdby);
  metadata->initializedfields[0] |= ATKEY_METADATA_CREATEDBY_INITIALIZED;
  ret = 0;
  goto exit;
exit: {
  return ret;
}
}

static int set_updatedby(atclient_atkey_metadata *metadata, const char *updatedby, const size_t updatedbylen) {
  int ret = 1;
  if(atclient_atkey_metadata_is_updatedby_initialized(*metadata)) {
    atclient_atsign_free(&metadata->updatedby);
  }
  atclient_atsign_init(&metadata->updatedby, updatedby);
  metadata->initializedfields[0] |= ATKEY_METADATA_UPDATEDBY_INITIALIZED;
  ret = 0;
  goto exit;
exit: {
  return ret;
}
}

static int set_status(atclient_atkey_metadata *metadata, const char *status, const size_t statuslen) {
  int ret = 1;
  if(atclient_atkey_metadata_is_status_initialized(*metadata)) {
    atclient_atstr_free(&metadata->status);
  }
  if((ret = atclient_atstr_init_literal(&metadata->status, statuslen, status)) != 0) {
    atclient_atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atclient_atstr_init_literal failed with string \"%.*s\"\n", statuslen, status);
    goto exit;
  }
  metadata->initializedfields[0] |= ATKEY_METADATA_STATUS_INITIALIZED;
  ret = 0;
  goto exit;
exit: {
  return ret;
}
}

static void set_version(atclient_atkey_metadata *metadata, int version) {
  metadata->version = version;
  metadata->initializedfields[0] |= ATKEY_METADATA_VERSION_INITIALIZED;
}

static int set_expiresat(atclient_atkey_metadata *metadata, const char *expiresat, const size_t expiresatlen) {
  int ret = 1;
  if(atclient_atkey_metadata_is_expiresat_initialized(*metadata)) {
    atclient_atstr_free(&metadata->expiresat);
  }
  if((ret = atclient_atstr_init_literal(&metadata->expiresat, expiresatlen, expiresat)) != 0) {
    atclient_atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atclient_atstr_init_literal failed with string \"%.*s\"\n", expiresatlen, expiresat);
    goto exit;
  }
  metadata->initializedfields[0] |= ATKEY_METADATA_EXPIRESAT_INITIALIZED;
  ret = 0;
  goto exit;
exit: {
  return ret;
}
}

static int set_availableat(atclient_atkey_metadata *metadata, const char *availableat, const size_t availableatlen) {
  int ret = 1;
  if(atclient_atkey_metadata_is_availableat_initialized(*metadata)) {
    atclient_atstr_free(&metadata->availableat);
  }
  if((ret = atclient_atstr_init_literal(&metadata->availableat, availableatlen, availableat)) != 0) {
    atclient_atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atclient_atstr_init_literal failed with string \"%.*s\"\n", availableatlen, availableat);
    goto exit;
  }
  metadata->initializedfields[0] |= ATKEY_METADATA_AVAILABLEAT_INITIALIZED;
  ret = 0;
  goto exit;
exit: {
  return ret;
}
}

static int set_refreshat(atclient_atkey_metadata *metadata, const char *refreshat, const size_t refreshatlen) {
  int ret = 1;
  if(atclient_atkey_metadata_is_refreshat_initialized(*metadata)) {
    atclient_atstr_free(&metadata->refreshat);
  }
  if ((ret = atclient_atstr_init_literal(&metadata->refreshat, refreshatlen, refreshat)) != 0) {
    atclient_atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atclient_atstr_init_literal failed with string \"%.*s\"\n", refreshatlen, refreshat);
    goto exit;
  }
  metadata->initializedfields[0] |= ATKEY_METADATA_REFRESHAT_INITIALIZED;
  ret = 0;
  goto exit;
exit: {
  return ret;
}
}

static int set_createdat(atclient_atkey_metadata *metadata, const char *createdat, const size_t createdatlen) {
  int ret = 1;
  if(atclient_atkey_metadata_is_createdat_initialized(*metadata)) {
    atclient_atstr_free(&metadata->createdat);
  }
  if ((ret = atclient_atstr_init_literal(&metadata->createdat, createdatlen, createdat)) != 0) {
    atclient_atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atclient_atstr_init_literal failed with string \"%.*s\"\n", createdatlen, createdat);
    goto exit;
  }
  metadata->initializedfields[0] |= ATKEY_METADATA_CREATEDAT_INITIALIZED;
  ret = 0;
  goto exit;
exit: {
  return ret;
}
}

static int set_updatedat(atclient_atkey_metadata *metadata, const char *updatedat, const size_t updatedatlen) {
  int ret = 1;
  if(atclient_atkey_metadata_is_updatedat_initialized(*metadata)) {
    atclient_atstr_free(&metadata->updatedat);
  }
  if ((ret = atclient_atstr_init_literal(&metadata->updatedat, updatedatlen, updatedat)) != 0) {
    atclient_atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atclient_atstr_init_literal failed with string \"%.*s\"\n", updatedatlen, updatedat);
    goto exit;
  }
  metadata->initializedfields[1] |= ATKEY_METADATA_UPDATEDAT_INITIALIZED;
  ret = 0;
  goto exit;
exit: {
  return ret;
}
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

static int set_datasignature(atclient_atkey_metadata *metadata, const char *datasignature, const size_t datasignaturelen) {
  int ret = 1;
  if(atclient_atkey_metadata_is_datasignature_initialized(*metadata)) {
    atclient_atstr_free(&metadata->datasignature);
  }
  if ((ret = atclient_atstr_init_literal(&metadata->datasignature, datasignaturelen, datasignature)) != 0) {
    atclient_atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atclient_atstr_init_literal failed with string \"%.*s\"\n", datasignaturelen, datasignature);
    goto exit;
  }
  metadata->initializedfields[2] |= ATKEY_METADATA_DATASIGNATURE_INITIALIZED;
  ret = 0;
  goto exit;
exit: {
  return ret;
}
}

static int set_sharedkeystatus(atclient_atkey_metadata *metadata, const char *sharedkeystatus, const size_t sharedkeystatuslen) {
  int ret = 1;
  if(atclient_atkey_metadata_is_sharedkeystatus_initialized(*metadata)) {
    atclient_atsign_free(&metadata->sharedkeystatus);
  }
  atclient_atsign_init(&metadata->sharedkeystatus, sharedkeystatus);
  metadata->initializedfields[2] |= ATKEY_METADATA_SHAREDKEYSTATUS_INITIALIZED;
  ret = 0;
  goto exit;
exit: {
  return ret;
}
}

static int set_sharedkeyenc(atclient_atkey_metadata *metadata, const char *sharedkeyenc, const size_t sharedkeyenclen) {
  int ret = 1;
  if(atclient_atkey_metadata_is_sharedkeyenc_initialized(*metadata)) {
    atclient_atsign_free(&metadata->sharedkeyenc);
  }
  atclient_atsign_init(&metadata->sharedkeyenc, sharedkeyenc);
  metadata->initializedfields[2] |= ATKEY_METADATA_SHAREDKEYENC_INITIALIZED;
  ret = 0;
  goto exit;
exit: {
  return ret;
}
}

static int set_pubkeyhash(atclient_atkey_metadata *metadata, const char *pubkeyhash, const size_t pubkeyhashlen) {
  int ret = 1;
  if(atclient_atkey_metadata_is_pubkeyhash_initialized(*metadata)) {
    atclient_atstr_free(&metadata->pubkeyhash);
  }
  if ((ret = atclient_atstr_init_literal(&metadata->pubkeyhash, pubkeyhashlen, pubkeyhash)) != 0) {
    atclient_atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atclient_atstr_init_literal failed with string \"%.*s\"\n", pubkeyhashlen, pubkeyhash);
    goto exit;
  }
  metadata->initializedfields[2] |= ATKEY_METADATA_PUBKEYHASH_INITIALIZED;
  ret = 0;
  goto exit;
exit: {
  return ret;
}
}

static int set_pubkeyalgo(atclient_atkey_metadata *metadata, const char *pubkeyalgo, const size_t pubkeyalgolen) {
  int ret = 1;
  if(atclient_atkey_metadata_is_pubkeyalgo_initialized(*metadata)) {
    atclient_atstr_free(&metadata->pubkeyalgo);
  }
  if ((ret = atclient_atstr_init_literal(&metadata->pubkeyalgo, pubkeyalgolen, pubkeyalgo)) != 0) {
    atclient_atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atclient_atstr_init_literal failed with string \"%.*s\"\n", pubkeyalgolen, pubkeyalgo);
    goto exit;
  }
  metadata->initializedfields[2] |= ATKEY_METADATA_PUBKEYALGO_INITIALIZED;
  ret = 0;
  goto exit;
exit: {
  return ret;
}
}

static int set_encoding(atclient_atkey_metadata *metadata, const char *encoding, const size_t encodinglen) {
  int ret = 1;
  if(atclient_atkey_metadata_is_encoding_initialized(*metadata)) {
    atclient_atstr_free(&metadata->encoding);
  }
  if ((ret = atclient_atstr_init_literal(&metadata->encoding, encodinglen, encoding)) != 0) {
    atclient_atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atclient_atstr_init_literal failed with string \"%.*s\"\n", encodinglen, encoding);
    goto exit;
  }
  metadata->initializedfields[2] |= ATKEY_METADATA_ENCODING_INITIALIZED;
  ret = 0;
  goto exit;
exit: {
  return ret;
}
}

static int set_enckeyname(atclient_atkey_metadata *metadata, const char *enckeyname, const size_t enckeynamelen) {
  int ret = 1;
  if(atclient_atkey_metadata_is_enckeyname_initialized(*metadata)) {
    atclient_atsign_free(&metadata->enckeyname);
  }
  atclient_atsign_init(&metadata->enckeyname, enckeyname);
  metadata->initializedfields[2] |= ATKEY_METADATA_ENCKEYNAME_INITIALIZED;
  ret = 0;
  goto exit;
exit: {
  return ret;
}
}

static int set_encalgo(atclient_atkey_metadata *metadata, const char *encalgo, const size_t encalgolen) {
  int ret = 1;
  if(atclient_atkey_metadata_is_encalgo_initialized(*metadata)) {
    atclient_atstr_free(&metadata->encalgo);
  }
  if ((ret = atclient_atstr_init_literal(&metadata->encalgo, encalgolen, encalgo)) != 0) {
    atclient_atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atclient_atstr_init_literal failed with string \"%.*s\"\n", encalgolen, encalgo);
    goto exit;
  }
  metadata->initializedfields[2] |= ATKEY_METADATA_ENCALGO_INITIALIZED;
  ret = 0;
  goto exit;
exit: {
  return ret;
}
}

static int set_ivnonce(atclient_atkey_metadata *metadata, const char *ivnonce, const size_t ivnoncelen) {
  int ret = 1;
  if(atclient_atkey_metadata_is_ivnonce_initialized(*metadata)) {
    atclient_atstr_free(&metadata->ivnonce);
  }
  if ((ret = atclient_atstr_init_literal(&metadata->ivnonce, ivnoncelen, ivnonce)) != 0) {
    atclient_atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atclient_atstr_init_literal failed with string \"%.*s\"\n", ivnoncelen, ivnonce);
    goto exit;
  }
  metadata->initializedfields[3] |= ATKEY_METADATA_IVNONCE_INITIALIZED;
  ret = 0;
  goto exit;
exit: {
  return ret;
}
}

static int set_skeenckeyname(atclient_atkey_metadata *metadata, const char *skeenckeyname, const size_t skeenckeynamelen) {
  int ret = 1;
  if(atclient_atkey_metadata_is_skeenckeyname_initialized(*metadata)) {
    atclient_atsign_free(&metadata->skeenckeyname);
  }
  atclient_atsign_init(&metadata->skeenckeyname, skeenckeyname);
  metadata->initializedfields[3] |= ATKEY_METADATA_SKEENCKEYNAME_INITIALIZED;
  ret = 0;
  goto exit;
exit: {
  return ret;
}
}

static int set_skeencalgo(atclient_atkey_metadata *metadata, const char *skeencalgo, const size_t skeencalgolen) {
  int ret = 1;
  if(atclient_atkey_metadata_is_skeencalgo_initialized(*metadata)) {
    atclient_atstr_free(&metadata->skeencalgo);
  }
  if ((ret = atclient_atstr_init_literal(&metadata->skeencalgo, skeencalgolen, skeencalgo)) != 0) {
    atclient_atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atclient_atstr_init_literal failed with string \"%.*s\"\n", skeencalgolen, skeencalgo);
    goto exit;
  }
  metadata->initializedfields[3] |= ATKEY_METADATA_SKEENCALGO_INITIALIZED;
  ret = 0;
  goto exit;
exit: {
  return ret;
}
}


bool atclient_atkey_metadata_is_createdby_initialized(const atclient_atkey_metadata metadata) {
  return metadata.initializedfields[0] & ATKEY_METADATA_CREATEDBY_INITIALIZED;
}

bool atclient_atkey_metadata_is_updatedby_initialized(const atclient_atkey_metadata metadata) {
  return metadata.initializedfields[0] & ATKEY_METADATA_UPDATEDBY_INITIALIZED;
}

bool atclient_atkey_metadata_is_status_initialized(const atclient_atkey_metadata metadata) {
  return metadata.initializedfields[0] & ATKEY_METADATA_STATUS_INITIALIZED;
}

bool atclient_atkey_metadata_is_availableat_initialized(const atclient_atkey_metadata metadata) {
  return metadata.initializedfields[0] & ATKEY_METADATA_AVAILABLEAT_INITIALIZED;
}

bool atclient_atkey_metadata_is_expiresat_initialized(const atclient_atkey_metadata metadata) {
  return metadata.initializedfields[0] & ATKEY_METADATA_EXPIRESAT_INITIALIZED;
}

bool atclient_atkey_metadata_is_refreshat_initialized(const atclient_atkey_metadata metadata) {
  return metadata.initializedfields[0] & ATKEY_METADATA_REFRESHAT_INITIALIZED;
}

bool atclient_atkey_metadata_is_createdat_initialized(const atclient_atkey_metadata metadata) {
  return metadata.initializedfields[0] & ATKEY_METADATA_CREATEDAT_INITIALIZED;
}

bool atclient_atkey_metadata_is_updatedat_initialized(const atclient_atkey_metadata metadata) {
  return metadata.initializedfields[1] & ATKEY_METADATA_UPDATEDAT_INITIALIZED;
}

bool atclient_atkey_metadata_is_ispublic_initialized(const atclient_atkey_metadata metadata) {
  return metadata.initializedfields[1] & ATKEY_METADATA_ISPUBLIC_INITIALIZED;
}

bool atclient_atkey_metadata_is_ishidden_initialized(const atclient_atkey_metadata metadata) {
  return metadata.initializedfields[1] & ATKEY_METADATA_ISHIDDEN_INITIALIZED;
}

bool atclient_atkey_metadata_is_iscached_initialized(const atclient_atkey_metadata metadata) {
  return metadata.initializedfields[1] & ATKEY_METADATA_ISCACHED_INITIALIZED;
}

bool atclient_atkey_metadata_is_ttl_initialized(const atclient_atkey_metadata metadata) {
  return metadata.initializedfields[1] & ATKEY_METADATA_TTL_INITIALIZED;
}

bool atclient_atkey_metadata_is_ttb_initialized(const atclient_atkey_metadata metadata) {
  return metadata.initializedfields[1] & ATKEY_METADATA_TTB_INITIALIZED;
}

bool atclient_atkey_metadata_is_ttr_initialized(const atclient_atkey_metadata metadata) {
  return metadata.initializedfields[1] & ATKEY_METADATA_TTR_INITIALIZED;
}

bool atclient_atkey_metadata_is_ccd_initialized(const atclient_atkey_metadata metadata) {
  return metadata.initializedfields[1] & ATKEY_METADATA_CCD_INITIALIZED;
}

bool atclient_atkey_metadata_is_isbinary_initialized(const atclient_atkey_metadata metadata) {
  return metadata.initializedfields[2] & ATKEY_METADATA_ISBINARY_INITIALIZED;
}

bool atclient_atkey_metadata_is_isencrypted_initialized(const atclient_atkey_metadata metadata) {
  return metadata.initializedfields[2] & ATKEY_METADATA_ISENCRYPTED_INITIALIZED;
}

bool atclient_atkey_metadata_is_datasignature_initialized(const atclient_atkey_metadata metadata) {
  return metadata.initializedfields[2] & ATKEY_METADATA_DATASIGNATURE_INITIALIZED;
}

bool atclient_atkey_metadata_is_sharedkeystatus_initialized(const atclient_atkey_metadata metadata) {
  return metadata.initializedfields[2] & ATKEY_METADATA_SHAREDKEYSTATUS_INITIALIZED;
}

bool atclient_atkey_metadata_is_sharedkeyenc_initialized(const atclient_atkey_metadata metadata) {
  return metadata.initializedfields[2] & ATKEY_METADATA_SHAREDKEYENC_INITIALIZED;
}

bool atclient_atkey_metadata_is_pubkeyhash_initialized(const atclient_atkey_metadata metadata) {
  return metadata.initializedfields[2] & ATKEY_METADATA_PUBKEYHASH_INITIALIZED;
}

bool atclient_atkey_metadata_is_pubkeyalgo_initialized(const atclient_atkey_metadata metadata) {
  return metadata.initializedfields[2] & ATKEY_METADATA_PUBKEYALGO_INITIALIZED;
}

bool atclient_atkey_metadata_is_encoding_initialized(const atclient_atkey_metadata metadata) {
  return metadata.initializedfields[2] & ATKEY_METADATA_ENCODING_INITIALIZED;
}

bool atclient_atkey_metadata_is_enckeyname_initialized(const atclient_atkey_metadata metadata) {
  return metadata.initializedfields[2] & ATKEY_METADATA_ENCKEYNAME_INITIALIZED;
}

bool atclient_atkey_metadata_is_encalgo_initialized(const atclient_atkey_metadata metadata) {
  return metadata.initializedfields[2] & ATKEY_METADATA_ENCALGO_INITIALIZED;
}

bool atclient_atkey_metadata_is_ivnonce_initialized(const atclient_atkey_metadata metadata) {
  return metadata.initializedfields[3] & ATKEY_METADATA_IVNONCE_INITIALIZED;
}

bool atclient_atkey_metadata_is_skeenckeyname_initialized(const atclient_atkey_metadata metadata) {
  return metadata.initializedfields[3] & ATKEY_METADATA_SKEENCKEYNAME_INITIALIZED;
}

bool atclient_atkey_metadata_is_skeencalgo_initialized(const atclient_atkey_metadata metadata) {
  return metadata.initializedfields[3] & ATKEY_METADATA_SKEENCALGO_INITIALIZED;
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

void atclient_atkey_metadata_set_ttl(atclient_atkey_metadata *metadata, const long ttl) {
  set_ttl(metadata, ttl);
}

void atclient_atkey_metadata_set_ttb(atclient_atkey_metadata *metadata, const long ttb) {
  set_ttb(metadata, ttb);
}

void atclient_atkey_metadata_set_ttr(atclient_atkey_metadata *metadata, const long ttr) {
  set_ttr(metadata, ttr);
}

void atclient_atkey_metadata_set_isbinary(atclient_atkey_metadata *metadata, const bool isbinary) {
  set_isbinary(metadata, isbinary);
}

void atclient_atkey_metadata_set_isencrypted(atclient_atkey_metadata *metadata, const bool isencrypted) {
  set_isencrypted(metadata, isencrypted);
}

int atclient_atkey_metadata_set_datasignature(atclient_atkey_metadata *metadata, const char *datasignature, const size_t datasignaturelen) {
  return set_datasignature(metadata, datasignature, datasignaturelen);
}

int atclient_atkey_metadata_set_sharedkeystatus(atclient_atkey_metadata *metadata, const char *sharedkeystatus, const size_t sharedkeystatuslen) {
  return set_sharedkeystatus(metadata, sharedkeystatus, sharedkeystatuslen);
}

int atclient_atkey_metadata_set_sharedkeyenc(atclient_atkey_metadata *metadata, const char *sharedkeyenc, const size_t sharedkeyenclen) {
  return set_sharedkeyenc(metadata, sharedkeyenc, sharedkeyenclen);
}

int atclient_atkey_metadata_set_pubkeyhash(atclient_atkey_metadata *metadata, const char *pubkeyhash, const size_t pubkeyhashlen) {
  return set_pubkeyhash(metadata, pubkeyhash, pubkeyhashlen);
}

int atclient_atkey_metadata_set_pubkeyalgo(atclient_atkey_metadata *metadata, const char *pubkeyalgo, const size_t pubkeyalgolen) {
  return set_pubkeyalgo(metadata, pubkeyalgo, pubkeyalgolen);
}

int atclient_atkey_metadata_set_encoding(atclient_atkey_metadata *metadata, const char *encoding, const size_t encodinglen) {
  return set_encoding(metadata, encoding, encodinglen);
}

int atclient_atkey_metadata_set_enckeyname(atclient_atkey_metadata *metadata, const char *enckeyname, const size_t enckeynamelen) {
  return set_enckeyname(metadata, enckeyname, enckeynamelen);
}

int atclient_atkey_metadata_set_encalgo(atclient_atkey_metadata *metadata, const char *encalgo, const size_t encalgolen) {
  return set_encalgo(metadata, encalgo, encalgolen);
}

int atclient_atkey_metadata_set_ivnonce(atclient_atkey_metadata *metadata, const char *ivnonce, const size_t ivnoncelen) {
  return set_ivnonce(metadata, ivnonce, ivnoncelen);
}

int atclient_atkey_metadata_set_skeenckeyname(atclient_atkey_metadata *metadata, const char *skeenckeyname, const size_t skeenckeynamelen) {
  return set_skeenckeyname(metadata, skeenckeyname, skeenckeynamelen);
}

int atclient_atkey_metadata_set_skeencalgo(atclient_atkey_metadata *metadata, const char *skeencalgo, const size_t skeencalgolen) {
  return set_skeencalgo(metadata, skeencalgo, skeencalgolen);
}

void atclient_atkey_metadata_free(atclient_atkey_metadata *metadata) {
  if(atclient_atkey_metadata_is_createdby_initialized(*metadata)) {
    atclient_atsign_free(&metadata->createdby);
  }

  if(atclient_atkey_metadata_is_updatedby_initialized(*metadata)) {
    atclient_atsign_free(&metadata->updatedby);
  }

  if(atclient_atkey_metadata_is_status_initialized(*metadata)) {
    atclient_atstr_free(&metadata->status);
  }

  if(atclient_atkey_metadata_is_availableat_initialized(*metadata)) {
    atclient_atstr_free(&metadata->availableat);
  }

  if(atclient_atkey_metadata_is_expiresat_initialized(*metadata)) {
    atclient_atstr_free(&metadata->expiresat);
  }

  if(atclient_atkey_metadata_is_refreshat_initialized(*metadata)) {
    atclient_atstr_free(&metadata->refreshat);
  }

  if(atclient_atkey_metadata_is_createdat_initialized(*metadata)) {
    atclient_atstr_free(&metadata->createdat);
  }

  if(atclient_atkey_metadata_is_updatedat_initialized(*metadata)) {
    atclient_atstr_free(&metadata->updatedat);
  }

  if(atclient_atkey_metadata_is_datasignature_initialized(*metadata)) {
    atclient_atstr_free(&metadata->datasignature);
  }

  if(atclient_atkey_metadata_is_sharedkeystatus_initialized(*metadata)) {
    atclient_atsign_free(&metadata->sharedkeystatus);
  }

  if(atclient_atkey_metadata_is_sharedkeyenc_initialized(*metadata)) {
    atclient_atsign_free(&metadata->sharedkeyenc);
  }

  if(atclient_atkey_metadata_is_pubkeyhash_initialized(*metadata)) {
    atclient_atstr_free(&metadata->pubkeyhash);
  }

  if(atclient_atkey_metadata_is_pubkeyalgo_initialized(*metadata)) {
    atclient_atstr_free(&metadata->pubkeyalgo);
  }

  if(atclient_atkey_metadata_is_encoding_initialized(*metadata)) {
    atclient_atstr_free(&metadata->encoding);
  }

  if(atclient_atkey_metadata_is_enckeyname_initialized(*metadata)) {
    atclient_atsign_free(&metadata->enckeyname);
  }

  if(atclient_atkey_metadata_is_encalgo_initialized(*metadata)) {
    atclient_atstr_free(&metadata->encalgo);
  }

  if(atclient_atkey_metadata_is_ivnonce_initialized(*metadata)) {
    atclient_atstr_free(&metadata->ivnonce);
  }

  if(atclient_atkey_metadata_is_skeenckeyname_initialized(*metadata)) {
    atclient_atsign_free(&metadata->skeenckeyname);
  }

  if(atclient_atkey_metadata_is_skeencalgo_initialized(*metadata)) {
    atclient_atstr_free(&metadata->skeencalgo);
  }
}
