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

bool atclient_atkey_metadata_is_createdby_initialized(const atclient_atkey_metadata metadata) {
  return metadata.initializedfields[0] & 0b00000001;
}

bool atclient_atkey_metadata_is_updatedby_initialized(const atclient_atkey_metadata metadata) {
  return metadata.initializedfields[0] & 0b00000010;
}

bool atclient_atkey_metadata_is_status_initialized(const atclient_atkey_metadata metadata) {
  return metadata.initializedfields[0] & 0b00000100;
}

bool atclient_atkey_metadata_is_availableat_initialized(const atclient_atkey_metadata metadata) {
  return metadata.initializedfields[0] & 0b00001000;
}

bool atclient_atkey_metadata_is_expiresat_initialized(const atclient_atkey_metadata metadata) {
  return metadata.initializedfields[0] & 0b00010000;
}

bool atclient_atkey_metadata_is_refreshat_initialized(const atclient_atkey_metadata metadata) {
  return metadata.initializedfields[0] & 0b00100000;
}

bool atclient_atkey_metadata_is_createdat_initialized(const atclient_atkey_metadata metadata) {
  return metadata.initializedfields[0] & 0b01000000;
}

bool atclient_atkey_metadata_is_updatedat_initialized(const atclient_atkey_metadata metadata) {
  return metadata.initializedfields[0] & 0b10000000;
}

bool atclient_atkey_metadata_is_datasignature_initialized(const atclient_atkey_metadata metadata) {
  return metadata.initializedfields[1] & 0b00000001;
}

bool atclient_atkey_metadata_is_sharedkeystatus_initialized(const atclient_atkey_metadata metadata) {
  return metadata.initializedfields[1] & 0b00000010;
}

bool atclient_atkey_metadata_is_sharedkeyenc_initialized(const atclient_atkey_metadata metadata) {
  return metadata.initializedfields[1] & 0b00000100;
}

bool atclient_atkey_metadata_is_pubkeyhash_initialized(const atclient_atkey_metadata metadata) {
  return metadata.initializedfields[1] & 0b00001000;
}

bool atclient_atkey_metadata_is_pubkeyalgo_initialized(const atclient_atkey_metadata metadata) {
  return metadata.initializedfields[1] & 0b00010000;
}

bool atclient_atkey_metadata_is_encoding_initialized(const atclient_atkey_metadata metadata) {
  return metadata.initializedfields[1] & 0b00100000;
}

bool atclient_atkey_metadata_is_enckeyname_initialized(const atclient_atkey_metadata metadata) {
  return metadata.initializedfields[1] & 0b01000000;
}

bool atclient_atkey_metadata_is_encalgo_initialized(const atclient_atkey_metadata metadata) {
  return metadata.initializedfields[1] & 0b10000000;
}

bool atclient_atkey_metadata_is_ivnonce_initialized(const atclient_atkey_metadata metadata) {
  return metadata.initializedfields[2] & 0b00000001;
}






void atclient_atkey_metadata_free(atclient_atkey_metadata *metadata) {
  
}
