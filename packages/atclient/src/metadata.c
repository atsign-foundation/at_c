#include "atclient/metadata.h"
#include "atclient/atsign.h"
#include "atclient/atstr.h"
#include "atclient/atsign.h"
#include "atlogger/atlogger.h"
#include "cJSON/cJSON.h"
#include <stdlib.h>
#include <string.h>

#define TAG "metadata"

void atclient_atkey_metadata_init(atclient_atkey_metadata *metadata) {
  memset(metadata, 0, sizeof(atclient_atkey_metadata));

  metadata->ttl = 0; // 0 is our null value, fall back to protocol default
  metadata->ttb = 0; // 0 is our null value, fall back to protocol default
  metadata->ttr = -2; // -2 is our null value, fall back to protocol default
  metadata->ccd = false;
  atclient_atstr_init(&(metadata->availableat), DATE_STR_BUFFER_SIZE);
  atclient_atstr_init(&(metadata->expiresat), DATE_STR_BUFFER_SIZE);
  atclient_atstr_init(&(metadata->refreshat), DATE_STR_BUFFER_SIZE);
  atclient_atstr_init(&(metadata->createdat), DATE_STR_BUFFER_SIZE);
  atclient_atstr_init(&(metadata->updatedat), DATE_STR_BUFFER_SIZE);
  atclient_atstr_init(&(metadata->datasignature), GENERAL_BUFFER_SIZE);
  atclient_atstr_init(&(metadata->sharedkeystatus), GENERAL_BUFFER_SIZE);
  metadata->ispublic = false;
  metadata->ishidden = false;
  metadata->isbinary = false;
  metadata->isencrypted = false;
  metadata->iscached = false;
  atclient_atstr_init(&(metadata->sharedkeyenc), GENERAL_BUFFER_SIZE);
  atclient_atstr_init(&(metadata->pubkeyhash), GENERAL_BUFFER_SIZE);
  atclient_atstr_init(&(metadata->pubkeyalgo), GENERAL_BUFFER_SIZE);
  atclient_atstr_init(&(metadata->encoding), GENERAL_BUFFER_SIZE);
  atclient_atstr_init(&(metadata->enckeyname), GENERAL_BUFFER_SIZE);
  atclient_atstr_init(&(metadata->encalgo), GENERAL_BUFFER_SIZE);
  atclient_atstr_init(&(metadata->ivnonce), GENERAL_BUFFER_SIZE);
  atclient_atstr_init(&(metadata->skeenckeyname), GENERAL_BUFFER_SIZE);
  atclient_atstr_init(&(metadata->skeencalgo), GENERAL_BUFFER_SIZE);
}

int atclient_atkey_metadata_from_string(atclient_atkey_metadata *metadata, const char *metadatastr, const unsigned long metadatastrlen) {
  // example:
  // "metaData":{
  //  "createdBy":"@qt_thermostat",
  //  "updatedBy":"@qt_thermostat",
  //  "createdAt":"2024-02-17 19:54:12.037Z",
  //  "updatedAt":"2024-02-17 19:54:12.037Z",
  //  "expiresAt":"2024-02-17 19:55:38.437Z",
  //  "status":"active",
  //  "version":0,
  //  "ttl":86400,
  //  "isBinary":false,
  //  "isEncrypted":false
  // }
  int ret = 1;

  cJSON *root = NULL;

  if(metadatastr == NULL) {
    ret = 1;
    atclient_atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atclient_atkey_metadata_from_string: metadatastr is NULL\n");
    goto exit;
  }

  if(metadatastrlen == 0) {
    ret = 1;
    atclient_atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atclient_atkey_metadata_from_string: metadatastrlen is 0\n");
    goto exit;
  }

  root = cJSON_Parse(metadatastr);
  if (root == NULL) {
    ret = 1;
    atclient_atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atclient_atkey_metadata_from_string: failed to parse metadata string: \"%s\"\n", metadatastr);
    goto exit;
  }

  cJSON *availableat = cJSON_GetObjectItem(root, "availableAt");
  if (availableat != NULL) {
    if (availableat->valuestring != NULL) {
      atclient_atstr_set(&(metadata->availableat), availableat->valuestring, strlen(availableat->valuestring));
    }
  }

  cJSON *expiresat = cJSON_GetObjectItem(root, "expiresAt");
  if (expiresat != NULL) {
    if (expiresat->valuestring != NULL) {
      atclient_atstr_set(&(metadata->expiresat), expiresat->valuestring, strlen(expiresat->valuestring));
    }
  }

  cJSON *refreshat = cJSON_GetObjectItem(root, "refreshAt");
  if (refreshat != NULL) {
    if (refreshat->valuestring != NULL) {
      atclient_atstr_set(&(metadata->refreshat), refreshat->valuestring, strlen(refreshat->valuestring));
    }
  }

  cJSON *createdat = cJSON_GetObjectItem(root, "createdAt");
  if (createdat != NULL) {
    if (createdat->valuestring != NULL) {
      atclient_atstr_set(&(metadata->createdat), createdat->valuestring, strlen(createdat->valuestring));
    }
  }

  cJSON *updatedat = cJSON_GetObjectItem(root, "updatedAt");
  if (updatedat != NULL) {
    if (updatedat->valuestring != NULL) {
      atclient_atstr_set(&(metadata->updatedat), updatedat->valuestring, strlen(updatedat->valuestring));
    }
  }

  cJSON *datasignature = cJSON_GetObjectItem(root, "dataSignature");
  if (datasignature != NULL) {
    if (datasignature->valuestring != NULL) {
      atclient_atstr_set(&(metadata->datasignature), datasignature->valuestring, strlen(datasignature->valuestring));
    }
  }

  cJSON *sharedkeystatus = cJSON_GetObjectItem(root, "sharedKeyStatus");
  if (sharedkeystatus != NULL) {
    if (sharedkeystatus->valuestring != NULL) {
      atclient_atstr_set(&(metadata->sharedkeystatus), sharedkeystatus->valuestring, strlen(sharedkeystatus->valuestring));
    }
  }

  cJSON *ispublic = cJSON_GetObjectItem(root, "isPublic");
  if(ispublic != NULL) {
    metadata->ispublic = cJSON_IsTrue(ispublic);
  }

  cJSON *ishidden = cJSON_GetObjectItem(root, "isHidden");
  if(ishidden != NULL) {
    metadata->ishidden = cJSON_IsTrue(ishidden);
  }

  cJSON *isbinary = cJSON_GetObjectItem(root, "isBinary");
  if (isbinary != NULL) {
    metadata->isbinary = cJSON_IsTrue(isbinary);
  }

  cJSON *isencrypted = cJSON_GetObjectItem(root, "isEncrypted");
  if (isencrypted != NULL) {
    metadata->isencrypted = cJSON_IsTrue(isencrypted);
  }

  cJSON *ttl = cJSON_GetObjectItem(root, "ttl");
  if (ttl != NULL) {
    metadata->ttl = ttl->valueint;
  }

  cJSON *ttb = cJSON_GetObjectItem(root, "ttb");
  if (ttb != NULL) {
    metadata->ttb = ttb->valueint;
  }

  cJSON *ttr = cJSON_GetObjectItem(root, "ttr");
  if (ttr != NULL) {
    metadata->ttr = ttr->valueint;
  }

  cJSON *ccd = cJSON_GetObjectItem(root, "ccd");
  if (ccd != NULL) {
    metadata->ccd = cJSON_IsTrue(ccd);
  }

  cJSON *sharedkeyenc = cJSON_GetObjectItem(root, "sharedKeyEnc");
  if (sharedkeyenc != NULL) {
    if (sharedkeyenc->valuestring != NULL) {
      atclient_atstr_set(&(metadata->sharedkeyenc), sharedkeyenc->valuestring, strlen(sharedkeyenc->valuestring));
    }
  }

  cJSON *pubkeyhash = cJSON_GetObjectItem(root, "pubKeyHash");
  if (pubkeyhash != NULL) {
    if (pubkeyhash->valuestring != NULL) {
      atclient_atstr_set(&(metadata->pubkeyhash), pubkeyhash->valuestring, strlen(pubkeyhash->valuestring));
    }
  }

  cJSON *pubkeyalgo = cJSON_GetObjectItem(root, "pubKeyAlgo");
  if (pubkeyalgo != NULL) {
    if (pubkeyalgo->valuestring != NULL) {
      atclient_atstr_set(&(metadata->pubkeyalgo), pubkeyalgo->valuestring, strlen(pubkeyalgo->valuestring));
    }
  }

  cJSON *encoding = cJSON_GetObjectItem(root, "encoding");
  if (encoding != NULL) {
    if (encoding->valuestring != NULL) {
      atclient_atstr_set(&(metadata->encoding), encoding->valuestring, strlen(encoding->valuestring));
    }
  }

  cJSON *ivnonce = cJSON_GetObjectItem(root, "ivNonce");
  if (ivnonce != NULL) {
    if (ivnonce->valuestring != NULL) {
      atclient_atstr_set(&(metadata->ivnonce), ivnonce->valuestring, strlen(ivnonce->valuestring));
    }
  }

  cJSON *enckeyname = cJSON_GetObjectItem(root, "encKeyName");
  if (enckeyname != NULL) {
    if (enckeyname->valuestring != NULL) {
      atclient_atstr_set(&(metadata->enckeyname), enckeyname->valuestring, strlen(enckeyname->valuestring));
    }
  }

  cJSON *encalgo = cJSON_GetObjectItem(root, "encAlgo");
  if (encalgo != NULL) {
    if (encalgo->valuestring != NULL) {
      atclient_atstr_set(&(metadata->encalgo), encalgo->valuestring, strlen(encalgo->valuestring));
    }
  }

  cJSON *skeenckeyname = cJSON_GetObjectItem(root, "skeEncKeyName");
  if (skeenckeyname != NULL) {
    if (skeenckeyname->valuestring != NULL) {
      atclient_atstr_set(&(metadata->skeenckeyname), skeenckeyname->valuestring, strlen(skeenckeyname->valuestring));
    }
  }

  cJSON *skeencalgo = cJSON_GetObjectItem(root, "skeEncAlgo");
  if (skeencalgo != NULL) {
    if (skeencalgo->valuestring != NULL) {
      atclient_atstr_set(&(metadata->skeencalgo), skeencalgo->valuestring, strlen(skeencalgo->valuestring));
    }
  }

  ret = 0;
  goto exit;

exit: {
  return ret;
}
}

int atclient_atkey_metadata_to_jsonstr(const atclient_atkey_metadata metadata, char *metadatastr,
                                      const unsigned long metadatastrlen, unsigned long *metadatastrolen) {
  // example:
  // "metaData":{
  //  "createdBy":"@qt_thermostat",
  //  "updatedBy":"@qt_thermostat",
  //  "createdAt":"2024-02-17 19:54:12.037Z",
  //  "updatedAt":"2024-02-17 19:54:12.037Z",
  //  "expiresAt":"2024-02-17 19:55:38.437Z",
  //  "status":"active",
  //  "version":0,
  //  "ttl":86400,
  //  "isBinary":false,
  //  "isEncrypted":false
  // }

  int ret = 1;

  cJSON *root = cJSON_CreateObject();
  if (root == NULL) {
    ret = 1;
    goto exit;
  }

  cJSON *createdby = cJSON_CreateString(metadata.createdby.str);
  if (createdby == NULL) {
    ret = 1;
    goto exit;
  }

  cJSON *updatedby = cJSON_CreateString(metadata.updatedby.str);
  if (updatedby == NULL) {
    ret = 1;
    goto exit;
  }

  cJSON *createdat = cJSON_CreateString(metadata.createdat.str);
  if (createdat == NULL) {
    ret = 1;
    goto exit;
  }

  cJSON *updatedat = cJSON_CreateString(metadata.updatedat.str);
  if (updatedat == NULL) {
    ret = 1;
    goto exit;
  }

  cJSON *status = cJSON_CreateString(metadata.status.str);
  if (status == NULL) {
    ret = 1;
    goto exit;
  }

  cJSON *datasignature = cJSON_CreateString(metadata.datasignature.str);
  if (datasignature == NULL) {
    ret = 1;
    goto exit;
  }

  cJSON *version = cJSON_CreateNumber(metadata.version);
  if (version == NULL) {
    ret = 1;
    goto exit;
  }

  cJSON *ttl = cJSON_CreateNumber(metadata.ttl);
  if (ttl == NULL) {
    ret = 1;
    goto exit;
  }

  cJSON *ttb = cJSON_CreateNumber(metadata.ttb);
  if (ttb == NULL) {
    ret = 1;
    goto exit;
  }

  cJSON *ttr = cJSON_CreateNumber(metadata.ttr);
  if (ttr == NULL) {
    ret = 1;
    goto exit;
  }

  cJSON *ccd = cJSON_CreateBool(metadata.ccd);
  if (ccd == NULL) {
    ret = 1;
    goto exit;
  }

  cJSON *isbinary = cJSON_CreateBool(metadata.isbinary);
  if (isbinary == NULL) {
    ret = 1;
    goto exit;
  }

  cJSON *isencrypted = cJSON_CreateBool(metadata.isencrypted);
  if (isencrypted == NULL) {
    ret = 1;
    goto exit;
  }

  cJSON *sharedkeyenc = cJSON_CreateString(metadata.sharedkeyenc.str);
  if (sharedkeyenc == NULL) {
    ret = 1;
    goto exit;
  }

  cJSON *pubkeyhash = cJSON_CreateString(metadata.pubkeyhash.str);
  if (pubkeyhash == NULL) {
    ret = 1;
    goto exit;
  }

  cJSON *pubkeyalgo = cJSON_CreateString(metadata.pubkeyalgo.str);
  if (pubkeyalgo == NULL) {
    ret = 1;
    goto exit;
  }

  cJSON *encoding = cJSON_CreateString(metadata.encoding.str);
  if (encoding == NULL) {
    ret = 1;
    goto exit;
  }

  cJSON *ivnonce = cJSON_CreateString(metadata.ivnonce.str);
  if (ivnonce == NULL) {
    ret = 1;
    goto exit;
  }

  cJSON *enckeyname = cJSON_CreateString(metadata.enckeyname.str);
  if (enckeyname == NULL) {
    ret = 1;
    goto exit;
  }

  cJSON *encalgo = cJSON_CreateString(metadata.encalgo.str);
  if (encalgo == NULL) {
    ret = 1;
    goto exit;
  }

  cJSON *skeenckeyname = cJSON_CreateString(metadata.skeenckeyname.str);
  if (skeenckeyname == NULL) {
    ret = 1;
    goto exit;
  }

  cJSON *skeencalgo = cJSON_CreateString(metadata.skeencalgo.str);
  if (skeencalgo == NULL) {
    ret = 1;
    goto exit;
  }

  cJSON *availableat = cJSON_CreateString(metadata.availableat.str);
  if (availableat == NULL) {
    ret = 1;
    goto exit;
  }

  cJSON *expiresat = cJSON_CreateString(metadata.expiresat.str);
  if (expiresat == NULL) {
    ret = 1;
    goto exit;
  }

  cJSON *refreshat = cJSON_CreateString(metadata.refreshat.str);
  if (refreshat == NULL) {
    ret = 1;
    goto exit;
  }

  cJSON *iscached = cJSON_CreateBool(metadata.iscached);
  if (iscached == NULL) {
    ret = 1;
    goto exit;
  }

  cJSON *ispublic = cJSON_CreateBool(metadata.ispublic);
  if(ispublic == NULL) {
    ret = 1;
    goto exit;
  }

  cJSON *ishidden = cJSON_CreateBool(metadata.ishidden);
  if(ishidden == NULL) {
    ret = 1;
    goto exit;
  }

  cJSON_bool success;
  success = cJSON_AddItemToObject(root, "createdBy", createdby);
  if(!success) {
    ret = 1;
    goto exit;
  }

  success = cJSON_AddItemToObject(root, "updatedBy", updatedby);
  if(!success) {
    ret = 1;
    goto exit;
  }

  success = cJSON_AddItemToObject(root, "createdAt", createdat);
  if(!success) {
    ret = 1;
    goto exit;
  }

  success = cJSON_AddItemToObject(root, "updatedAt", updatedat);
  if(!success) {
    ret = 1;
    goto exit;
  }

  success = cJSON_AddItemToObject(root, "status", status);
  if(!success) {
    ret = 1;
    goto exit;
  }

  success = cJSON_AddItemToObject(root, "dataSignature", datasignature);
  if(!success) {
    ret = 1;
    goto exit;
  }

  success = cJSON_AddItemToObject(root, "version", version);
  if(!success) {
    ret = 1;
    goto exit;
  }

  success = cJSON_AddItemToObject(root, "ttl", ttl);
  if(!success) {
    ret = 1;
    goto exit;
  }

  success = cJSON_AddItemToObject(root, "ttb", ttb);
  if(!success) {
    ret = 1;
    goto exit;
  }

  success = cJSON_AddItemToObject(root, "ttr", ttr);
  if(!success) {
    ret = 1;
    goto exit;
  }

  success = cJSON_AddItemToObject(root, "isBinary", isbinary);
  if(!success) {
    ret = 1;
    goto exit;
  }

  success = cJSON_AddItemToObject(root, "isEncrypted", isencrypted);
  if(!success) {
    ret = 1;
    goto exit;
  }

  success = cJSON_AddItemToObject(root, "sharedKeyEnc", sharedkeyenc);
  if(!success) {
    ret = 1;
    goto exit;
  }

  success = cJSON_AddItemToObject(root, "pubKeyHash", pubkeyhash);
  if(!success) {
    ret = 1;
    goto exit;
  }

  success = cJSON_AddItemToObject(root, "pubKeyAlgo", pubkeyalgo);
  if(!success) {
    ret = 1;
    goto exit;
  }

  success = cJSON_AddItemToObject(root, "encoding", encoding);
  if(!success) {
    ret = 1;
    goto exit;
  }

  success = cJSON_AddItemToObject(root, "ivNonce", ivnonce);
  if(!success) {
    ret = 1;
    goto exit;
  }

  success = cJSON_AddItemToObject(root, "encKeyName", enckeyname);
  if(!success) {
    ret = 1;
    goto exit;
  }

  success = cJSON_AddItemToObject(root, "encAlgo", encalgo);
  if(!success) {
    ret = 1;
    goto exit;
  }

  success = cJSON_AddItemToObject(root, "skeEncKeyName", skeenckeyname);
  if(!success) {
    ret = 1;
    goto exit;
  }

  success = cJSON_AddItemToObject(root, "skeEncAlgo", skeencalgo);
  if(!success) {
    ret = 1;
    goto exit;
  }

  success = cJSON_AddItemToObject(root, "availableAt", availableat);
  if(!success) {
    ret = 1;
    goto exit;
  }

  success = cJSON_AddItemToObject(root, "expiresAt", expiresat);
  if(!success) {
    ret = 1;
    goto exit;
  }

  success = cJSON_AddItemToObject(root, "refreshAt", refreshat);
  if(!success) {
    ret = 1;
    goto exit;
  }

  success = cJSON_AddItemToObject(root, "isCached", iscached);
  if(!success) {
    ret = 1;
    goto exit;
  }

  success = cJSON_AddItemToObject(root, "isPublic", ispublic);
  if(!success) {
    ret = 1;
    goto exit;
  }

  success = cJSON_AddItemToObject(root, "isHidden", ishidden);
  if(!success) {
    ret = 1;
    goto exit;
  }

  char *jsonstr = cJSON_Print(root);
  if (jsonstr == NULL) {
    ret = 1;
    goto exit;
  }

  if (strlen(jsonstr) > metadatastrlen) {
    ret = 1;
    goto exit;
  }

  strcpy(metadatastr, jsonstr);
  *metadatastrolen = strlen(jsonstr);

  ret = 0;
  goto exit;
exit: {
  cJSON_Delete(root);
  return ret;
}
}

int atclient_atkey_metadata_to_protocolstr(const atclient_atkey_metadata metadata, char *metadatastr, const size_t metadatastrlen, size_t *metadatastrolen) {
  int ret = 1;

  atclient_atstr buffer;
  atclient_atstr_init(&buffer, metadatastrlen);

  if(metadatastrlen == 0) {
    ret = 1;
    atclient_atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atclient_atkey_metadata_to_protocolstr: metadatastrlen is 0\n");
    goto exit;
  }

  if(metadatastrolen == NULL) {
    ret = 1;
    atclient_atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atclient_atkey_metadata_to_protocolstr: metadatastrolen is NULL\n");
    goto exit;
  }

  if(metadata.ttl > 0) {
    ret = atclient_atstr_append(&buffer, ":ttl:%ld", metadata.ttl);
    if(ret != 0) {
      atclient_atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atclient_atkey_metadata_to_protocolstr: failed to append ttl\n");
      goto exit;
    }
  }

  if(metadata.ttb > 0) {
    ret = atclient_atstr_append(&buffer, ":ttb:%ld", metadata.ttb);
    if(ret != 0) {
      atclient_atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atclient_atkey_metadata_to_protocolstr: failed to append ttb\n");
      goto exit;
    }
  }

  if(metadata.ttr != -2) {
    ret = atclient_atstr_append(&buffer, ":ttr:%ld", metadata.ttr);
    if(ret != 0) {
      atclient_atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atclient_atkey_metadata_to_protocolstr: failed to append ttr\n");
      goto exit;
    }
  }

  if(metadata.ccd) {
    ret = atclient_atstr_append(&buffer, ":ccd:true");
    if(ret != 0) {
      atclient_atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atclient_atkey_metadata_to_protocolstr: failed to append ccd\n");
      goto exit;
    }
  }

  if(metadata.isbinary) {
    ret = atclient_atstr_append(&buffer, ":isBinary:true");
    if(ret != 0) {
      atclient_atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atclient_atkey_metadata_to_protocolstr: failed to append isBinary\n");
      goto exit;
    }
  }

  if(metadata.isencrypted) {
    ret = atclient_atstr_append(&buffer, ":isEncrypted:true");
    if(ret != 0) {
      atclient_atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atclient_atkey_metadata_to_protocolstr: failed to append isEncrypted\n");
      goto exit;
    }
  }

  if(metadata.sharedkeyenc.olen > 0) {
    ret = atclient_atstr_append(&buffer, ":sharedKeyEnc:%.*s", (int) metadata.sharedkeyenc.olen, metadata.sharedkeyenc.str);
    if(ret != 0) {
      atclient_atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atclient_atkey_metadata_to_protocolstr: failed to append sharedKeyEnc\n");
      goto exit;
    }
  }

  if(metadata.pubkeyhash.olen > 0 && metadata.pubkeyalgo.olen > 0) {
    ret = atclient_atstr_append(&buffer, ":hash:%.*s", (int) metadata.pubkeyhash.olen, metadata.pubkeyhash.str);
    if(ret != 0) {
      atclient_atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atclient_atkey_metadata_to_protocolstr: failed to append pubKeyHash\n");
      goto exit;
    }
    ret = atclient_atstr_append(&buffer, ":algo:%.*s", (int) metadata.pubkeyalgo.olen, metadata.pubkeyalgo.str);
    if(ret != 0) {
      atclient_atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atclient_atkey_metadata_to_protocolstr: failed to append pubKeyAlgo\n");
      goto exit;
    }
  }

  if(metadata.encoding.olen > 0) {
    ret = atclient_atstr_append(&buffer, ":encoding:%.*s", (int) metadata.encoding.olen, metadata.encoding.str);
    if(ret != 0) {
      atclient_atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atclient_atkey_metadata_to_protocolstr: failed to append encoding\n");
      goto exit;
    }
  }

  if(metadata.ivnonce.olen > 0) {
    ret = atclient_atstr_append(&buffer, ":ivNonce:%.*s", (int) metadata.ivnonce.olen, metadata.ivnonce.str);
    if(ret != 0) {
      atclient_atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atclient_atkey_metadata_to_protocolstr: failed to append ivNonce\n");
      goto exit;
    }
  }

  if(metadata.enckeyname.olen > 0) {
    ret = atclient_atstr_append(&buffer, ":encKeyName:%.*s", (int) metadata.enckeyname.olen, metadata.enckeyname.str);
    if(ret != 0) {
      atclient_atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atclient_atkey_metadata_to_protocolstr: failed to append encKeyName\n");
      goto exit;
    }
  }

  if(metadata.encalgo.olen > 0) {
    ret = atclient_atstr_append(&buffer, ":encAlgo:%.*s", (int) metadata.encalgo.olen, metadata.encalgo.str);
    if(ret != 0) {
      atclient_atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atclient_atkey_metadata_to_protocolstr: failed to append encAlgo\n");
      goto exit;
    }
  }

  if(metadata.skeenckeyname.olen > 0) {
    ret = atclient_atstr_append(&buffer, ":skeEncKeyName:%.*s", (int) metadata.skeenckeyname.olen, metadata.skeenckeyname.str);
    if(ret != 0) {
      atclient_atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atclient_atkey_metadata_to_protocolstr: failed to append skeEncKeyName\n");
      goto exit;
    }
  }

  if(metadata.skeencalgo.olen > 0) {
    ret = atclient_atstr_append(&buffer, ":skeEncAlgo:%.*s", (int) metadata.skeencalgo.olen, metadata.skeencalgo.str);
    if(ret != 0) {
      atclient_atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atclient_atkey_metadata_to_protocolstr: failed to append skeEncAlgo\n");
      goto exit;
    }
  }

  memcpy(metadatastr, buffer.str, buffer.olen);
  *metadatastrolen = buffer.olen;

  ret = 0;
  goto exit;
  
exit: {
  atclient_atstr_free(&buffer);
  return ret;
}
}

void atclient_atkey_metadata_free(atclient_atkey_metadata *metadata) {
  atclient_atstr_free(&(metadata->availableat));
  atclient_atstr_free(&(metadata->expiresat));
  atclient_atstr_free(&(metadata->refreshat));
  atclient_atstr_free(&(metadata->createdat));
  atclient_atstr_free(&(metadata->updatedat));
  atclient_atstr_free(&(metadata->datasignature));
  atclient_atstr_free(&(metadata->sharedkeystatus));
  atclient_atstr_free(&(metadata->sharedkeyenc));
  atclient_atstr_free(&(metadata->pubkeyhash));
  atclient_atstr_free(&(metadata->pubkeyalgo));
  atclient_atstr_free(&(metadata->encoding));
  atclient_atstr_free(&(metadata->ivnonce));
  atclient_atstr_free(&(metadata->enckeyname));
  atclient_atstr_free(&(metadata->encalgo));

}
