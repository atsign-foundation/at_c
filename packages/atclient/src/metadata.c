#include "atclient/metadata.h"
#include "atclient/stringutils.h"
#include "atlogger/atlogger.h"
#include "cJSON.h"
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define TAG "metadata"

static bool is_created_by_initialized(const atclient_atkey_metadata *metadata);
static bool is_updated_by_initialized(const atclient_atkey_metadata *metadata);
static bool is_status_initialized(const atclient_atkey_metadata *metadata);
static bool is_version_initialized(const atclient_atkey_metadata *metadata);
static bool is_expires_at_initialized(const atclient_atkey_metadata *metadata);
static bool is_available_at_initialized(const atclient_atkey_metadata *metadata);
static bool is_refresh_at_initialized(const atclient_atkey_metadata *metadata);
static bool is_created_at_initialized(const atclient_atkey_metadata *metadata);
static bool is_updated_at_initialized(const atclient_atkey_metadata *metadata);
static bool is_is_public_initialized(const atclient_atkey_metadata *metadata);
static bool is_is_cached_initialized(const atclient_atkey_metadata *metadata);
static bool is_ttl_initialized(const atclient_atkey_metadata *metadata);
static bool is_ttb_initialized(const atclient_atkey_metadata *metadata);
static bool is_ttr_initialized(const atclient_atkey_metadata *metadata);
static bool is_ccd_initialized(const atclient_atkey_metadata *metadata);
static bool is_is_binary_initialized(const atclient_atkey_metadata *metadata);
static bool is_is_encrypted_initialized(const atclient_atkey_metadata *metadata);
static bool is_data_signature_initialized(const atclient_atkey_metadata *metadata);
static bool is_shared_key_status_initialized(const atclient_atkey_metadata *metadata);
static bool is_shared_key_enc_initialized(const atclient_atkey_metadata *metadata);
static bool is_pub_key_hash_initialized(const atclient_atkey_metadata *metadata);
static bool is_pub_key_algo_initialized(const atclient_atkey_metadata *metadata);
static bool is_encoding_initialized(const atclient_atkey_metadata *metadata);
static bool is_enc_key_name_initialized(const atclient_atkey_metadata *metadata);
static bool is_enc_algo_initialized(const atclient_atkey_metadata *metadata);
static bool is_iv_nonce_initialized(const atclient_atkey_metadata *metadata);
static bool is_ske_enc_key_name_initialized(const atclient_atkey_metadata *metadata);
static bool is_ske_enc_algo_initialized(const atclient_atkey_metadata *metadata);

static void set_is_created_by_initialized(atclient_atkey_metadata *metadata, bool is_initialized);
static void set_is_updated_by_initialized(atclient_atkey_metadata *metadata, bool is_initialized);
static void set_is_status_initialized(atclient_atkey_metadata *metadata, bool is_initialized);
static void set_is_version_initialized(atclient_atkey_metadata *metadata, bool is_initialized);
static void set_is_available_at_initialized(atclient_atkey_metadata *metadata, bool is_initialized);
static void set_is_expires_at_initialized(atclient_atkey_metadata *metadata, bool is_initialized);
static void set_is_refresh_at_initialized(atclient_atkey_metadata *metadata, bool is_initialized);
static void set_is_created_at_initialized(atclient_atkey_metadata *metadata, bool is_initialized);
static void set_is_updated_at_initialized(atclient_atkey_metadata *metadata, bool is_initialized);
static void set_is_is_public_initialized(atclient_atkey_metadata *metadata, bool is_initialized);
static void set_is_is_cached_initialized(atclient_atkey_metadata *metadata, bool is_initialized);
static void set_is_ttl_initialized(atclient_atkey_metadata *metadata, bool is_initialized);
static void set_is_ttb_initialized(atclient_atkey_metadata *metadata, bool is_initialized);
static void set_is_ttr_initialized(atclient_atkey_metadata *metadata, bool is_initialized);
static void set_is_ccd_initialized(atclient_atkey_metadata *metadata, bool is_initialized);
static void set_is_is_binary_initialized(atclient_atkey_metadata *metadata, bool is_initialized);
static void set_is_is_encrypted_initialized(atclient_atkey_metadata *metadata, bool is_initialized);
static void set_is_data_signature_initialized(atclient_atkey_metadata *metadata, bool is_initialized);
static void set_is_shared_key_status_initialized(atclient_atkey_metadata *metadata, bool is_initialized);
static void set_is_shared_key_enc_initialized(atclient_atkey_metadata *metadata, bool is_initialized);
static void set_is_pub_key_hash_initialized(atclient_atkey_metadata *metadata, bool is_initialized);
static void set_is_pub_key_algo_initialized(atclient_atkey_metadata *metadata, bool is_initialized);
static void set_is_encoding_initialized(atclient_atkey_metadata *metadata, bool is_initialized);
static void set_is_enc_key_name_initialized(atclient_atkey_metadata *metadata, bool is_initialized);
static void set_is_enc_algo_initialized(atclient_atkey_metadata *metadata, bool is_initialized);
static void set_is_iv_nonce_initialized(atclient_atkey_metadata *metadata, bool is_initialized);
static void set_is_ske_enc_key_name_initialized(atclient_atkey_metadata *metadata, bool is_initialized);
static void set_is_ske_enc_algo_initialized(atclient_atkey_metadata *metadata, bool is_initialized);

static void unset_created_by(atclient_atkey_metadata *metadata);
static void unset_updated_by(atclient_atkey_metadata *metadata);
static void unset_status(atclient_atkey_metadata *metadata);
static void unset_version(atclient_atkey_metadata *metadata);
static void unset_expires_at(atclient_atkey_metadata *metadata);
static void unset_available_at(atclient_atkey_metadata *metadata);
static void unset_refresh_at(atclient_atkey_metadata *metadata);
static void unset_created_at(atclient_atkey_metadata *metadata);
static void unset_updated_at(atclient_atkey_metadata *metadata);
static void unset_is_public(atclient_atkey_metadata *metadata);
static void unset_is_cached(atclient_atkey_metadata *metadata);
static void unset_ttl(atclient_atkey_metadata *metadata);
static void unset_ttb(atclient_atkey_metadata *metadata);
static void unset_ttr(atclient_atkey_metadata *metadata);
static void unset_ccd(atclient_atkey_metadata *metadata);
static void unset_is_binary(atclient_atkey_metadata *metadata);
static void unset_is_encrypted(atclient_atkey_metadata *metadata);
static void unset_data_signature(atclient_atkey_metadata *metadata);
static void unset_shared_key_status(atclient_atkey_metadata *metadata);
static void unset_shared_key_enc(atclient_atkey_metadata *metadata);
static void unset_pub_key_hash(atclient_atkey_metadata *metadata);
static void unset_pub_key_algo(atclient_atkey_metadata *metadata);
static void unset_encoding(atclient_atkey_metadata *metadata);
static void unset_enc_key_name(atclient_atkey_metadata *metadata);
static void unset_enc_algo(atclient_atkey_metadata *metadata);
static void unset_iv_nonce(atclient_atkey_metadata *metadata);
static void unset_ske_enc_key_name(atclient_atkey_metadata *metadata);
static void unset_ske_enc_algo(atclient_atkey_metadata *metadata);

static int set_created_by(atclient_atkey_metadata *metadata, const char *created_by);
static int set_updated_by(atclient_atkey_metadata *metadata, const char *updated_by);
static int set_status(atclient_atkey_metadata *metadata, const char *status);
static void set_version(atclient_atkey_metadata *metadata, int version);
static int set_expires_at(atclient_atkey_metadata *metadata, const char *expires_at);
static int set_available_at(atclient_atkey_metadata *metadata, const char *available_at);
static int set_refresh_at(atclient_atkey_metadata *metadata, const char *refresh_at);
static int set_created_at(atclient_atkey_metadata *metadata, const char *created_at);
static int set_updated_at(atclient_atkey_metadata *metadata, const char *updated_at);
static void set_is_public(atclient_atkey_metadata *metadata, const bool is_public);
static void set_is_cached(atclient_atkey_metadata *metadata, const bool is_cached);
static void set_ttl(atclient_atkey_metadata *metadata, const long ttl);
static void set_ttb(atclient_atkey_metadata *metadata, const long ttb);
static void set_ttr(atclient_atkey_metadata *metadata, const long ttr);
static void set_ccd(atclient_atkey_metadata *metadata, const bool ccd);
static void set_is_binary(atclient_atkey_metadata *metadata, const bool is_binary);
static void set_is_encrypted(atclient_atkey_metadata *metadata, const bool is_encrypted);
static int set_data_signature(atclient_atkey_metadata *metadata, const char *data_signature);
static int set_shared_key_status(atclient_atkey_metadata *metadata, const char *shared_key_status);
static int set_shared_key_enc(atclient_atkey_metadata *metadata, const char *shared_key_enc);
static int set_pub_key_hash(atclient_atkey_metadata *metadata, const char *pub_key_hash);
static int set_pubkeyalgo(atclient_atkey_metadata *metadata, const char *pub_key_algo);
static int set_encoding(atclient_atkey_metadata *metadata, const char *encoding);
static int set_enc_key_name(atclient_atkey_metadata *metadata, const char *enc_key_name);
static int set_enc_algo(atclient_atkey_metadata *metadata, const char *enc_algo);
static int set_iv_nonce(atclient_atkey_metadata *metadata, const char *iv_nonce);
static int set_ske_enc_key_name(atclient_atkey_metadata *metadata, const char *ske_enc_key_name);
static int set_ske_enc_algo(atclient_atkey_metadata *metadata, const char *ske_enc_algo);

void atclient_atkey_metadata_init(atclient_atkey_metadata *metadata) {
  memset(metadata, 0, sizeof(atclient_atkey_metadata));
}

int atclient_atkey_metadata_clone(atclient_atkey_metadata *dst, const atclient_atkey_metadata *src) {
  int ret = 1;

  if (dst == NULL) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "dst is NULL\n");
    goto exit;
  }

  if (src == NULL) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "src is NULL\n");
    goto exit;
  }

  if (atclient_atkey_metadata_is_created_by_initialized(src)) {
    if ((ret = set_created_by(dst, src->created_by)) != 0) {
      atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "set_created_by: %d\n", ret);
      goto exit;
    }
  }

  if (atclient_atkey_metadata_is_updated_by_initialized(src)) {
    if ((ret = set_updated_by(dst, src->updated_by)) != 0) {
      atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "set_updated_by: %d\n", ret);
      goto exit;
    }
  }

  if (atclient_atkey_metadata_is_status_initialized(src)) {
    if ((ret = set_status(dst, src->status)) != 0) {
      atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "set_status: %d\n", ret);
      goto exit;
    }
  }

  if (atclient_atkey_metadata_is_version_initialized(src)) {
    set_version(dst, src->version);
  }

  if (atclient_atkey_metadata_is_expires_at_initialized(src)) {
    if ((ret = set_expires_at(dst, src->expires_at)) != 0) {
      atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "set_expires_at: %d\n", ret);
      goto exit;
    }
  }

  if (atclient_atkey_metadata_is_available_at_initialized(src)) {
    if ((ret = set_available_at(dst, src->available_at)) != 0) {
      atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "set_available_at: %d\n", ret);
      goto exit;
    }
  }

  if (atclient_atkey_metadata_is_refresh_at_initialized(src)) {
    if ((ret = set_refresh_at(dst, src->refresh_at)) != 0) {
      atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "set_refresh_at: %d\n", ret);
      goto exit;
    }
  }

  if (atclient_atkey_metadata_is_created_at_initialized(src)) {
    if ((ret = set_created_at(dst, src->created_at)) != 0) {
      atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "set_created_at: %d\n", ret);
      goto exit;
    }
  }

  if (atclient_atkey_metadata_is_updated_at_initialized(src)) {
    if ((ret = set_updated_at(dst, src->updated_at)) != 0) {
      atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "set_updated_at: %d\n", ret);
      goto exit;
    }
  }

  if (atclient_atkey_metadata_is_is_public_initialized(src)) {
    set_is_public(dst, src->is_public);
  }

  if (atclient_atkey_metadata_is_is_cached_initialized(src)) {
    set_is_cached(dst, src->is_cached);
  }

  if (atclient_atkey_metadata_is_ttl_initialized(src)) {
    set_ttl(dst, src->ttl);
  }

  if (atclient_atkey_metadata_is_ttb_initialized(src)) {
    set_ttb(dst, src->ttb);
  }

  if (atclient_atkey_metadata_is_ttr_initialized(src)) {
    set_ttr(dst, src->ttr);
  }

  if (atclient_atkey_metadata_is_ccd_initialized(src)) {
    set_ccd(dst, src->ccd);
  }

  if (atclient_atkey_metadata_is_is_binary_initialized(src)) {
    set_is_binary(dst, src->is_binary);
  }

  if (atclient_atkey_metadata_is_is_encrypted_initialized(src)) {
    set_is_encrypted(dst, src->is_encrypted);
  }

  if (atclient_atkey_metadata_is_data_signature_initialized(src)) {
    if ((ret = set_data_signature(dst, src->data_signature)) != 0) {
      atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "set_data_signature: %d\n", ret);
      goto exit;
    }
  }

  if (atclient_atkey_metadata_is_shared_key_status_initialized(src)) {
    if ((ret = set_shared_key_status(dst, src->shared_key_status)) != 0) {
      atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "set_shared_key_status: %d\n", ret);
      goto exit;
    }
  }

  if (atclient_atkey_metadata_is_shared_key_enc_initialized(src)) {
    if ((ret = set_shared_key_enc(dst, src->shared_key_enc)) != 0) {
      atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "set_shared_key_enc: %d\n", ret);
      goto exit;
    }
  }

  if (atclient_atkey_metadata_is_pub_key_hash_initialized(src)) {
    if ((ret = set_pub_key_hash(dst, src->pub_key_hash)) != 0) {
      atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "set_pub_key_hash: %d\n", ret);
      goto exit;
    }
  }

  if (atclient_atkey_metadata_is_pub_key_algo_initialized(src)) {
    if ((ret = set_pubkeyalgo(dst, src->pub_key_algo)) != 0) {
      atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "set_pubkeyalgo: %d\n", ret);
      goto exit;
    }
  }

  if (atclient_atkey_metadata_is_encoding_initialized(src)) {
    if ((ret = set_encoding(dst, src->encoding)) != 0) {
      atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "set_encoding: %d\n", ret);
      goto exit;
    }
  }

  if (atclient_atkey_metadata_is_enc_key_name_initialized(src)) {
    if ((ret = set_enc_key_name(dst, src->enc_key_name)) != 0) {
      atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "set_enc_key_name: %d\n", ret);
      goto exit;
    }
  }

  if (atclient_atkey_metadata_is_enc_algo_initialized(src)) {
    if ((ret = set_enc_algo(dst, src->enc_algo)) != 0) {
      atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "set_enc_algo: %d\n", ret);
      goto exit;
    }
  }

  if (atclient_atkey_metadata_is_iv_nonce_initialized(src)) {
    if ((ret = set_iv_nonce(dst, src->iv_nonce)) != 0) {
      atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "set_iv_nonce: %d\n", ret);
      goto exit;
    }
  }

  if (atclient_atkey_metadata_is_ske_enc_key_name_initialized(src)) {
    if ((ret = set_ske_enc_key_name(dst, src->ske_enc_key_name)) != 0) {
      atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "set_ske_enc_key_name: %d\n", ret);
      goto exit;
    }
  }

  if (atclient_atkey_metadata_is_ske_enc_algo_initialized(src)) {
    if ((ret = set_ske_enc_algo(dst, src->ske_enc_algo)) != 0) {
      atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "set_ske_enc_algo: %d\n", ret);
      goto exit;
    }
  }

  ret = 0;
  goto exit;
exit: { return ret; }
}

int atclient_atkey_metadata_from_json_str(atclient_atkey_metadata *metadata, const char *metadata_str) {
  int ret = 1;

  /*
   * 1. Validate arguments
   */
  if (metadata == NULL) {
    ret = 1;
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "metadata is NULL\n");
    return ret;
  }

  if (metadata_str == NULL) {
    ret = 1;
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "metadata_str is NULL\n");
    return ret;
  }

  /*
   * 2. Parse JSON string
   */
  cJSON *root = cJSON_Parse(metadata_str);
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

  /*
   * 1. Validate arguments
   */

  if (json == NULL) {
    ret = 1;
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "json is NULL\n");
    return ret;
  }

  if (metadata == NULL) {
    ret = 1;
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "metadata is NULL\n");
    return ret;
  }

  /*
   * 2. Parse JSON node
   */

  cJSON *created_by = cJSON_GetObjectItem(json, "createdBy");
  if (created_by != NULL) {
    if (created_by->type != cJSON_NULL) {
      if ((ret = set_created_by(metadata, created_by->valuestring)) != 0) {
        atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "set_created_by: %d\n", ret);
        goto exit;
      }
    } else {
      if ((ret = set_created_by(metadata, "null")) != 0) {
        atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "set_created_by: %d\n", ret);
        goto exit;
      }
    }
  }

  cJSON *updated_by = cJSON_GetObjectItem(json, "updatedBy");
  if (updated_by != NULL) {
    if (updated_by->type != cJSON_NULL) {
      if ((ret = set_updated_by(metadata, updated_by->valuestring)) != 0) {
        atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "set_updated_by: %d\n", ret);
        goto exit;
      }
    } else {
      if ((ret = set_updated_by(metadata, "null")) != 0) {
        atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "set_updated_by: %d\n", ret);
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

  cJSON *expires_at = cJSON_GetObjectItem(json, "expiresAt");
  if (expires_at != NULL) {
    if (expires_at->type != cJSON_NULL) {
      if ((ret = set_expires_at(metadata, expires_at->valuestring)) != 0) {
        atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "set_expires_at: %d\n", ret);
        goto exit;
      }
    } else {
      if ((ret = set_expires_at(metadata, "null")) != 0) {
        atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "set_expires_at: %d\n", ret);
        goto exit;
      }
    }
  }

  cJSON *available_at = cJSON_GetObjectItem(json, "availableAt");
  if (available_at != NULL) {
    if (available_at->type != cJSON_NULL) {
      if ((ret = set_available_at(metadata, available_at->valuestring)) != 0) {
        atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "set_available_at: %d\n", ret);
        goto exit;
      }
    } else {
      if ((ret = set_available_at(metadata, "null")) != 0) {
        atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "set_available_at: %d\n", ret);
        goto exit;
      }
    }
  }

  cJSON *refresh_at = cJSON_GetObjectItem(json, "refreshAt");
  if (refresh_at != NULL) {
    if (refresh_at->type != cJSON_NULL) {
      if ((ret = set_refresh_at(metadata, refresh_at->valuestring)) != 0) {
        atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "set_refresh_at: %d\n", ret);
        goto exit;
      }
    } else {
      if ((ret = set_refresh_at(metadata, "null")) != 0) {
        atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "set_refresh_at: %d\n", ret);
        goto exit;
      }
    }
  }

  cJSON *created_at = cJSON_GetObjectItem(json, "createdAt");
  if (created_at != NULL) {
    if (created_at->type != cJSON_NULL) {
      if ((ret = set_created_at(metadata, created_at->valuestring)) != 0) {
        atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "set_created_at: %d\n", ret);
        goto exit;
      }
    } else {
      if ((ret = set_created_at(metadata, "null")) != 0) {
        atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "set_created_at: %d\n", ret);
        goto exit;
      }
    }
  }

  cJSON *updated_at = cJSON_GetObjectItem(json, "updatedAt");
  if (updated_at != NULL) {
    if (updated_at->type != cJSON_NULL) {
      if ((ret = set_updated_at(metadata, updated_at->valuestring)) != 0) {
        atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "set_updated_at: %d\n", ret);
        goto exit;
      }
    } else {
      if ((ret = set_updated_at(metadata, "null")) != 0) {
        atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "set_updated_at: %d\n", ret);
        goto exit;
      }
    }
  }

  // I don't think this field exists when reading metadata from atServer
  // cJSON *is_public = cJSON_GetObjectItem(root, "isPublic");
  // if(is_public != NULL) {
  //   set_is_public(metadata, is_public->valueint);
  // }

  // I don't think this field exists when reading metadata from atServer
  // cJSON *is_cached = cJSON_GetObjectItem(root, "isCached
  // if(is_cached != NULL) {
  //   set_is_cached(metadata, is_cached->valueint);
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
      set_ccd(metadata, false);
    }
  }

  cJSON *is_binary = cJSON_GetObjectItem(json, "isBinary");
  if (is_binary != NULL) {
    if (is_binary->type != cJSON_NULL) {
      set_is_binary(metadata, is_binary->valueint);
    } else {
      set_is_binary(metadata, false);
    }
  }

  cJSON *is_encrypted = cJSON_GetObjectItem(json, "isEncrypted");
  if (is_encrypted != NULL) {
    if (is_encrypted->type != cJSON_NULL) {
      set_is_encrypted(metadata, is_encrypted->valueint);
    } else {
      set_is_encrypted(metadata, false);
    }
  }

  cJSON *data_signature = cJSON_GetObjectItem(json, "dataSignature");
  if (data_signature != NULL) {
    if (data_signature->type != cJSON_NULL) {
      if ((ret = set_data_signature(metadata, data_signature->valuestring)) != 0) {
        atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "set_data_signature: %d\n", ret);
        goto exit;
      }
    } else {
      if ((ret = set_data_signature(metadata, "null")) != 0) {
        atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "set_data_signature: %d\n", ret);
        goto exit;
      }
    }
  }

  cJSON *shared_key_status = cJSON_GetObjectItem(json, "sharedKeyStatus");
  if (shared_key_status != NULL) {
    if (shared_key_status->type != cJSON_NULL) {
      if ((ret = set_shared_key_status(metadata, shared_key_status->valuestring)) != 0) {
        atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "set_shared_key_status: %d\n", ret);
        goto exit;
      }
    } else {
      if ((ret = set_shared_key_status(metadata, "null")) != 0) {
        atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "set_shared_key_status: %d\n", ret);
        goto exit;
      }
    }
  }

  cJSON *shared_key_enc = cJSON_GetObjectItem(json, "sharedKeyEnc");
  if (shared_key_enc != NULL) {
    if (shared_key_enc->type != cJSON_NULL) {
      if ((ret = set_shared_key_enc(metadata, shared_key_enc->valuestring)) != 0) {
        atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "set_shared_key_enc: %d\n", ret);
        goto exit;
      }
    } else {
      if ((ret = set_shared_key_enc(metadata, "null")) != 0) {
        atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "set_shared_key_enc: %d\n", ret);
        goto exit;
      }
    }
  }

  cJSON *pub_key_hash = cJSON_GetObjectItem(json, "pubKeyHash");
  if (pub_key_hash != NULL) {
    if (pub_key_hash->type != cJSON_NULL) {
      if ((ret = set_pub_key_hash(metadata, pub_key_hash->valuestring)) != 0) {
        atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "set_pub_key_hash: %d\n", ret);
        goto exit;
      }
    } else {
      if ((ret = set_pub_key_hash(metadata, "null")) != 0) {
        atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "set_pub_key_hash: %d\n", ret);
        goto exit;
      }
    }
  }

  cJSON *pub_key_algo = cJSON_GetObjectItem(json, "pubKeyAlgo");
  if (pub_key_algo != NULL) {
    if (pub_key_algo->type != cJSON_NULL) {
      if ((ret = set_pubkeyalgo(metadata, pub_key_algo->valuestring)) != 0) {
        atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "set_pubkeyalgo: %d\n", ret);
        goto exit;
      }
    } else {
      if ((ret = set_pubkeyalgo(metadata, "null")) != 0) {
        atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "set_pubkeyalgo: %d\n", ret);
        goto exit;
      }
    }
  }

  cJSON *encoding = cJSON_GetObjectItem(json, "encoding");
  if (encoding != NULL) {
    if (encoding->type != cJSON_NULL) {
      if ((ret = set_encoding(metadata, encoding->valuestring)) != 0) {
        atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "set_encoding: %d\n", ret);
        goto exit;
      }
    } else {
      if ((ret = set_encoding(metadata, "null")) != 0) {
        atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "set_encoding: %d\n", ret);
        goto exit;
      }
    }
  }

  cJSON *enc_key_name = cJSON_GetObjectItem(json, "encKeyName");
  if (enc_key_name != NULL) {
    if (enc_key_name->type != cJSON_NULL) {
      if ((ret = set_enc_key_name(metadata, enc_key_name->valuestring)) != 0) {
        atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "set_enc_key_name: %d\n", ret);
        goto exit;
      }
    } else {
      if ((ret = set_enc_key_name(metadata, "null")) != 0) {
        atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "set_enc_key_name: %d\n", ret);
        goto exit;
      }
    }
  }

  cJSON *enc_algo = cJSON_GetObjectItem(json, "encAlgo");
  if (enc_algo != NULL) {
    if (enc_algo->type != cJSON_NULL) {
      if ((ret = set_enc_algo(metadata, enc_algo->valuestring)) != 0) {
        atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "set_enc_algo: %d\n", ret);
        goto exit;
      }
    } else {
      if ((ret = set_enc_algo(metadata, "null")) != 0) {
        atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "set_enc_algo: %d\n", ret);
        goto exit;
      }
    }
  }

  cJSON *iv_nonce = cJSON_GetObjectItem(json, "ivNonce");
  if (iv_nonce != NULL) {
    if (iv_nonce->type != cJSON_NULL) {
      if ((ret = set_iv_nonce(metadata, iv_nonce->valuestring)) != 0) {
        atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "set_iv_nonce: %d\n", ret);
        goto exit;
      }
    } else {
      if ((ret = set_iv_nonce(metadata, "null")) != 0) {
        atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "set_iv_nonce: %d\n", ret);
        goto exit;
      }
    }
  }

  cJSON *ske_enc_key_name = cJSON_GetObjectItem(json, "skeEncKeyName");
  if (ske_enc_key_name != NULL) {
    if (ske_enc_key_name->type != cJSON_NULL) {
      if ((ret = set_ske_enc_key_name(metadata, ske_enc_key_name->valuestring)) != 0) {
        atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "set_ske_enc_key_name: %d\n", ret);
        goto exit;
      }
    } else {
      if ((ret = set_ske_enc_key_name(metadata, "null")) != 0) {
        atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "set_ske_enc_key_name: %d\n", ret);
        goto exit;
      }
    }
  }

  cJSON *ske_enc_algo = cJSON_GetObjectItem(json, "skeEncAlgo");
  if (ske_enc_algo != NULL) {
    if (ske_enc_algo->type != cJSON_NULL) {
      if ((ret = set_ske_enc_algo(metadata, ske_enc_algo->valuestring)) != 0) {
        atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "set_ske_enc_algo: %d\n", ret);
        goto exit;
      }
    } else {
      if ((ret = set_ske_enc_algo(metadata, "null")) != 0) {
        atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "set_ske_enc_algo: %d\n", ret);
        goto exit;
      }
    }
  }

  ret = 0;
  goto exit;
exit: { return ret; }
}

int atclient_atkey_metadata_to_json_str(const atclient_atkey_metadata *metadata, char **metadata_str) {
  int ret = 1;

  /*
   * 1. Validate arguments
   */
  if (metadata == NULL) {
    ret = 1;
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "metadata is NULL\n");
    return ret;
  }

  if (metadata_str == NULL) {
    ret = 1;
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "metadata_str is NULL\n");
    return ret;
  }

  /*
   * 2. Create JSON string
   */
  char *json_str = NULL;
  cJSON *root = cJSON_CreateObject();
  if (root == NULL) {
    ret = 1;
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "cJSON_CreateObject failed\n");
    goto exit;
  }

  if (atclient_atkey_metadata_is_created_by_initialized(metadata)) {
    cJSON_AddStringToObject(root, "createdBy", metadata->created_by);
  }

  if (atclient_atkey_metadata_is_updated_by_initialized(metadata)) {
    cJSON_AddStringToObject(root, "updatedBy", metadata->updated_by);
  }

  if (atclient_atkey_metadata_is_status_initialized(metadata)) {
    cJSON_AddStringToObject(root, "status", metadata->status);
  }

  if (atclient_atkey_metadata_is_version_initialized(metadata)) {
    cJSON_AddNumberToObject(root, "version", metadata->version);
  }

  if (atclient_atkey_metadata_is_expires_at_initialized(metadata)) {
    cJSON_AddStringToObject(root, "expiresAt", metadata->expires_at);
  }

  if (atclient_atkey_metadata_is_available_at_initialized(metadata)) {
    cJSON_AddStringToObject(root, "availableAt", metadata->available_at);
  }

  if (atclient_atkey_metadata_is_refresh_at_initialized(metadata)) {
    cJSON_AddStringToObject(root, "refreshAt", metadata->refresh_at);
  }

  if (atclient_atkey_metadata_is_created_at_initialized(metadata)) {
    cJSON_AddStringToObject(root, "createdAt", metadata->created_at);
  }

  if (atclient_atkey_metadata_is_updated_at_initialized(metadata)) {
    cJSON_AddStringToObject(root, "updatedAt", metadata->updated_at);
  }

  if (atclient_atkey_metadata_is_is_public_initialized(metadata)) {
    cJSON_AddBoolToObject(root, "isPublic", metadata->is_public);
  }

  if (atclient_atkey_metadata_is_is_cached_initialized(metadata)) {
    cJSON_AddBoolToObject(root, "isCached", metadata->is_cached);
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

  if (atclient_atkey_metadata_is_is_binary_initialized(metadata)) {
    cJSON_AddBoolToObject(root, "isBinary", metadata->is_binary);
  }

  if (atclient_atkey_metadata_is_is_encrypted_initialized(metadata)) {
    cJSON_AddBoolToObject(root, "isEncrypted", metadata->is_encrypted);
  }

  if (atclient_atkey_metadata_is_data_signature_initialized(metadata)) {
    cJSON_AddStringToObject(root, "dataSignature", metadata->data_signature);
  }

  if (atclient_atkey_metadata_is_shared_key_status_initialized(metadata)) {
    cJSON_AddStringToObject(root, "sharedKeyStatus", metadata->shared_key_status);
  }

  if (atclient_atkey_metadata_is_shared_key_enc_initialized(metadata)) {
    cJSON_AddStringToObject(root, "sharedKeyEnc", metadata->shared_key_enc);
  }

  if (atclient_atkey_metadata_is_pub_key_hash_initialized(metadata)) {
    cJSON_AddStringToObject(root, "pubKeyHash", metadata->pub_key_hash);
  }

  if (atclient_atkey_metadata_is_pub_key_algo_initialized(metadata)) {
    cJSON_AddStringToObject(root, "pubKeyAlgo", metadata->pub_key_algo);
  }

  if (atclient_atkey_metadata_is_encoding_initialized(metadata)) {
    cJSON_AddStringToObject(root, "encoding", metadata->encoding);
  }

  if (atclient_atkey_metadata_is_enc_key_name_initialized(metadata)) {
    cJSON_AddStringToObject(root, "encKeyName", metadata->enc_key_name);
  }

  if (atclient_atkey_metadata_is_enc_algo_initialized(metadata)) {
    cJSON_AddStringToObject(root, "encAlgo", metadata->enc_algo);
  }

  if (atclient_atkey_metadata_is_iv_nonce_initialized(metadata)) {
    cJSON_AddStringToObject(root, "ivNonce", metadata->iv_nonce);
  }

  if (atclient_atkey_metadata_is_ske_enc_key_name_initialized(metadata)) {
    cJSON_AddStringToObject(root, "skeEncKeyName", metadata->ske_enc_key_name);
  }

  if (atclient_atkey_metadata_is_ske_enc_algo_initialized(metadata)) {
    cJSON_AddStringToObject(root, "skeEncAlgo", metadata->ske_enc_algo);
  }

  json_str = cJSON_Print(root);
  if (json_str == NULL) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "cJSON_Print failed\n");
    goto exit;
  }

  const size_t metadata_str_size = strlen(json_str) + 1;
  *metadata_str = (char *)malloc(sizeof(char) * metadata_str_size);
  if (*metadata_str == NULL) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "malloc failed\n");
    goto exit;
  }
  memcpy(*metadata_str, json_str, strlen(json_str));
  (*metadata_str)[strlen(json_str)] = '\0';

  ret = 0;
  goto exit;
exit: {
  free(json_str);
  cJSON_Delete(root);
  return ret;
}
}

size_t atclient_atkey_metadata_protocol_strlen(const atclient_atkey_metadata *metadata) {
  /*
   * 1. Validate arguments
   */
  if (metadata == NULL) {
    return 0;
  }

  /*
   * 2. Calculate length
   */
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

  if (atclient_atkey_metadata_is_is_binary_initialized(metadata)) {
    len += atclient_atkey_metadata_is_binary_strlen(metadata);
  }

  if (atclient_atkey_metadata_is_is_encrypted_initialized(metadata)) {
    len += atclient_atkey_metadata_is_encrypted_strlen(metadata);
  }

  if (atclient_atkey_metadata_is_data_signature_initialized(metadata)) {
    len += atclient_atkey_metadata_data_signature_strlen(metadata);
  }

  if (atclient_atkey_metadata_is_shared_key_status_initialized(metadata)) {
    len += atclient_atkey_metadata_shared_key_status_strlen(metadata);
  }

  if (atclient_atkey_metadata_is_shared_key_enc_initialized(metadata)) {
    len += atclient_atkey_metadata_shared_key_enc_strlen(metadata);
  }

  if (atclient_atkey_metadata_is_pub_key_hash_initialized(metadata)) {
    len += atclient_atkey_metadata_pub_key_hash_strlen(metadata);
  }

  if (atclient_atkey_metadata_is_pub_key_algo_initialized(metadata)) {
    len += atclient_atkey_metadata_pub_key_algo_strlen(metadata);
  }

  if (atclient_atkey_metadata_is_encoding_initialized(metadata)) {
    len += atclient_atkey_metadata_encoding_strlen(metadata);
  }

  if (atclient_atkey_metadata_is_enc_key_name_initialized(metadata)) {
    len += atclient_atkey_metadata_enc_key_name_strlen(metadata);
  }

  if (atclient_atkey_metadata_is_enc_algo_initialized(metadata)) {
    len += atclient_atkey_metadata_enc_algo_strlen(metadata);
  }

  if (atclient_atkey_metadata_is_iv_nonce_initialized(metadata)) {
    len += atclient_atkey_metadata_iv_nonce_strlen(metadata);
  }

  if (atclient_atkey_metadata_is_ske_enc_key_name_initialized(metadata)) {
    len += atclient_atkey_metadata_ske_enc_key_name_strlen(metadata);
  }

  if (atclient_atkey_metadata_is_ske_enc_algo_initialized(metadata)) {
    len += atclient_atkey_metadata_ske_enc_algo_strlen(metadata);
  }

  return len;
}

size_t atclient_atkey_metadata_ttl_strlen(const atclient_atkey_metadata *metadata) {
  if (metadata == NULL) {
    return 0;
  }
  if (!atclient_atkey_metadata_is_ttl_initialized(metadata)) {
    return 0;
  }
  return strlen(":ttl:") // :ttl:
         + long_strlen(metadata->ttl);
}

size_t atclient_atkey_metadata_ttb_strlen(const atclient_atkey_metadata *metadata) {
  if(metadata == NULL) {
    return 0;
  }
  if(!atclient_atkey_metadata_is_ttb_initialized(metadata)) {
    return 0;
  }
  return strlen(":ttb:") // :ttb:
         + long_strlen(metadata->ttb);
}

size_t atclient_atkey_metadata_ttr_strlen(const atclient_atkey_metadata *metadata) {
  if(metadata == NULL) {
    return 0;
  }
  if(!atclient_atkey_metadata_is_ttr_initialized(metadata)) {
    return 0;
  }
  return strlen(":ttr:") // :ttr:
         + long_strlen(metadata->ttr);
}

size_t atclient_atkey_metadata_ccd_strlen(const atclient_atkey_metadata *metadata) {
  if(metadata == NULL) {
    return 0;
  }
  if(!atclient_atkey_metadata_is_ccd_initialized(metadata)) {
    return 0;
  }
  if (metadata->ccd) {
    return strlen(":ccd:true"); // :ccd:true
  } else {
    return strlen(":ccd:false"); // :ccd:false
  }
  return 0;
}

size_t atclient_atkey_metadata_is_binary_strlen(const atclient_atkey_metadata *metadata) {
  if(metadata == NULL) {
    return 0;
  }
  if(!atclient_atkey_metadata_is_is_binary_initialized(metadata)) {
    return 0;
  }
  if (metadata->is_binary) {
    return strlen(":isBinary:true");
  } else {
    return strlen(":isBinary:false");
  }
}

size_t atclient_atkey_metadata_is_encrypted_strlen(const atclient_atkey_metadata *metadata) {
  if(metadata == NULL) {
    return 0;
  }
  if(!atclient_atkey_metadata_is_is_encrypted_initialized(metadata)) {
    return 0;
  }
  if (metadata->is_encrypted) {
    return strlen(":isEncrypted:true");
  } else {
    return strlen(":isEncrypted:false");
  }
}

size_t atclient_atkey_metadata_data_signature_strlen(const atclient_atkey_metadata *metadata) {
  if(metadata == NULL) {
    return 0;
  }
  if(!atclient_atkey_metadata_is_data_signature_initialized(metadata)) {
    return 0;
  }
  return strlen(":dataSignature:") + strlen(metadata->data_signature);
}

size_t atclient_atkey_metadata_shared_key_status_strlen(const atclient_atkey_metadata *metadata) {
  if(metadata == NULL) {
    return 0;
  }
  if(!atclient_atkey_metadata_is_shared_key_status_initialized(metadata)) {
    return 0;
  }
  return strlen(":sharedKeyStatus:") + strlen(metadata->shared_key_status);
}

size_t atclient_atkey_metadata_shared_key_enc_strlen(const atclient_atkey_metadata *metadata) {
  if(metadata == NULL) {
    return 0;
  }
  if(!atclient_atkey_metadata_is_shared_key_enc_initialized(metadata)) {
    return 0;
  }
  return strlen(":sharedKeyEnc:") + strlen(metadata->shared_key_enc);
}

size_t atclient_atkey_metadata_pub_key_hash_strlen(const atclient_atkey_metadata *metadata) {
  if(metadata == NULL) {
    return 0;
  }
  if(!atclient_atkey_metadata_is_pub_key_hash_initialized(metadata)) {
    return 0;
  }
  return strlen(":hash:") + strlen(metadata->pub_key_hash);
}

size_t atclient_atkey_metadata_pub_key_algo_strlen(const atclient_atkey_metadata *metadata) {
  if(metadata == NULL) {
    return 0;
  }
  if(!atclient_atkey_metadata_is_pub_key_algo_initialized(metadata)) {
    return 0;
  }
  return strlen(":algo:") + strlen(metadata->pub_key_algo);
}

size_t atclient_atkey_metadata_encoding_strlen(const atclient_atkey_metadata *metadata) {
  if(metadata == NULL) {
    return 0;
  }
  if(!atclient_atkey_metadata_is_encoding_initialized(metadata)) {
    return 0;
  }
  return strlen(":encoding:") + strlen(metadata->encoding);
}

size_t atclient_atkey_metadata_enc_key_name_strlen(const atclient_atkey_metadata *metadata) {
  if(metadata == NULL) {
    return 0;
  }
  if(!atclient_atkey_metadata_is_enc_key_name_initialized(metadata)) {
    return 0;
  }
  return strlen(":encKeyName:") + strlen(metadata->enc_key_name);
}

size_t atclient_atkey_metadata_enc_algo_strlen(const atclient_atkey_metadata *metadata) {
  if(metadata == NULL) {
    return 0;
  }
  if(!atclient_atkey_metadata_is_enc_algo_initialized(metadata)) {
    return 0;
  }
  return strlen(":encAlgo:") + strlen(metadata->enc_algo);
}

size_t atclient_atkey_metadata_iv_nonce_strlen(const atclient_atkey_metadata *metadata) {
  if(metadata == NULL) {
    return 0;
  }
  if(!atclient_atkey_metadata_is_iv_nonce_initialized(metadata)) {
    return 0;
  }
  return strlen(":ivNonce:") + strlen(metadata->iv_nonce);
}

size_t atclient_atkey_metadata_ske_enc_key_name_strlen(const atclient_atkey_metadata *metadata) {
  if(metadata == NULL) {
    return 0;
  }
  if(!atclient_atkey_metadata_is_ske_enc_key_name_initialized(metadata)) {
    return 0;
  }
  return strlen(":skeEncKeyName:") + strlen(metadata->ske_enc_key_name);
}

size_t atclient_atkey_metadata_ske_enc_algo_strlen(const atclient_atkey_metadata *metadata) {
  if(metadata == NULL) {
    return 0;
  }
  if(!atclient_atkey_metadata_is_ske_enc_algo_initialized(metadata)) {
    return 0;
  }
  return strlen(":skeEncAlgo:") + strlen(metadata->ske_enc_algo);
}

int atclient_atkey_metadata_to_protocol_str(const atclient_atkey_metadata *metadata, char **metadata_str) {
  int ret = 1;

  /*
   * 1. Validate arguments
   */
  if (metadata == NULL) {
    ret = 1;
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "metadata is NULL\n");
    return ret;
  }

  if (metadata_str == NULL) {
    ret = 1;
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "metadata_str is NULL\n");
    return ret;
  }

  /*
   * 2. Create protocol string
   */
  const size_t metadata_str_size = atclient_atkey_metadata_protocol_strlen(metadata) + 1;
  const size_t expected_metadatastr_len = metadata_str_size - 1;
  size_t pos = 0;

  if ((*metadata_str = malloc(sizeof(char) * metadata_str_size)) == NULL) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "malloc failed\n");
    goto exit;
  }
  memset(*metadata_str, 0, sizeof(char) * metadata_str_size);

  if (atclient_atkey_metadata_is_ttl_initialized(metadata)) {
    sprintf(*metadata_str + pos, ":ttl:%ld", metadata->ttl);
    pos += 5 + long_strlen(metadata->ttl);
  }

  if (atclient_atkey_metadata_is_ttb_initialized(metadata)) {
    sprintf(*metadata_str + pos, ":ttb:%ld", metadata->ttb);
    pos += 5 + long_strlen(metadata->ttb);
  }

  if (atclient_atkey_metadata_is_ttr_initialized(metadata)) {
    sprintf(*metadata_str + pos, ":ttr:%ld", metadata->ttr);
    pos += 5 + long_strlen(metadata->ttr);
  }

  if (atclient_atkey_metadata_is_ccd_initialized(metadata)) {
    if (metadata->ccd) {
      sprintf(*metadata_str + pos, ":ccd:true");
      pos += 9;
    } else {
      sprintf(metadata_str + pos, ":ccd:false");
      pos += 10;
    }
  }

  if (atclient_atkey_metadata_is_is_binary_initialized(metadata)) {
    if (metadata->is_binary) {
      sprintf(*metadata_str + pos, ":isBinary:true");
      pos += 14;
    } else {
      sprintf(*metadata_str + pos, ":isBinary:false");
      pos += 15;
    }
  }

  if (atclient_atkey_metadata_is_is_encrypted_initialized(metadata)) {
    if (metadata->is_encrypted) {
      sprintf(*metadata_str + pos, ":isEncrypted:true");
      pos += 17;
    } else {
      sprintf(*metadata_str + pos, ":isEncrypted:false");
      pos += 18;
    }
  }

  if (atclient_atkey_metadata_is_data_signature_initialized(metadata)) {
    sprintf(*metadata_str + pos, ":dataSignature:%s", metadata->data_signature);
    pos += strlen(":dataSignature:") + strlen(metadata->data_signature);
  }

  if (atclient_atkey_metadata_is_shared_key_status_initialized(metadata)) {
    sprintf(*metadata_str + pos, ":sharedKeyStatus:%s", metadata->shared_key_status);
    pos += strlen(":sharedKeyStatus:") + strlen(metadata->shared_key_status);
  }

  if (atclient_atkey_metadata_is_shared_key_enc_initialized(metadata)) {
    sprintf(*metadata_str + pos, ":sharedKeyEnc:%s", metadata->shared_key_enc);
    pos += strlen(":sharedKeyEnc:") + strlen(metadata->shared_key_enc);
  }

  if (atclient_atkey_metadata_is_pub_key_hash_initialized(metadata)) {
    sprintf(*metadata_str + pos, ":hash:%s", metadata->pub_key_hash);
    pos += strlen(":hash:") + strlen(metadata->pub_key_hash);
  }

  if (atclient_atkey_metadata_is_pub_key_algo_initialized(metadata)) {
    sprintf(*metadata_str + pos, ":algo:%s", metadata->pub_key_algo);
    pos += strlen(":algo:") + strlen(metadata->pub_key_algo);
  }

  if (atclient_atkey_metadata_is_encoding_initialized(metadata)) {
    sprintf(*metadata_str + pos, ":encoding:%s", metadata->encoding);
    pos += strlen(":encoding:") + strlen(metadata->encoding);
  }

  if (atclient_atkey_metadata_is_enc_key_name_initialized(metadata)) {
    sprintf(*metadata_str + pos, ":encKeyName:%s", metadata->enc_key_name);
    pos += strlen(":encKeyName:") + strlen(metadata->enc_key_name);
  }

  if (atclient_atkey_metadata_is_enc_algo_initialized(metadata)) {
    sprintf(*metadata_str + pos, ":encAlgo:%s", metadata->enc_algo);
    pos += strlen(":encAlgo:") + strlen(metadata->enc_algo);
  }

  if (atclient_atkey_metadata_is_iv_nonce_initialized(metadata)) {
    sprintf(*metadata_str + pos, ":ivNonce:%s", metadata->iv_nonce);
    pos += strlen(":ivNonce:") + strlen(metadata->iv_nonce);
  }

  if (atclient_atkey_metadata_is_ske_enc_key_name_initialized(metadata)) {
    sprintf(*metadata_str + pos, ":skeEncKeyName:%s", metadata->ske_enc_key_name);
    pos += strlen(":skeEncKeyName:") + strlen(metadata->ske_enc_key_name);
  }

  if (atclient_atkey_metadata_is_ske_enc_algo_initialized(metadata)) {
    sprintf(*metadata_str + pos, ":skeEncAlgo:%s", metadata->ske_enc_algo);
    pos += strlen(":skeEncAlgo:") + strlen(metadata->ske_enc_algo);
  }

  /*
   * 3. Do a sanity check
   */
  if (strlen(*metadata_str) != (expected_metadatastr_len)) {
    ret = 1;
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "metadata_str length mismatch: %lu != %lu\n", strlen(*metadata_str),
                 (expected_metadatastr_len));
    goto exit;
  }

  ret = 0;
  goto exit;
exit: { return ret; }
}

bool atclient_atkey_metadata_is_created_by_initialized(const atclient_atkey_metadata *metadata) {
  return is_created_by_initialized(metadata);
}

bool atclient_atkey_metadata_is_updated_by_initialized(const atclient_atkey_metadata *metadata) {
  return is_updated_by_initialized(metadata);
}

bool atclient_atkey_metadata_is_status_initialized(const atclient_atkey_metadata *metadata) {
  return is_status_initialized(metadata);
}

bool atclient_atkey_metadata_is_version_initialized(const atclient_atkey_metadata *metadata) {
  return is_version_initialized(metadata);
}

bool atclient_atkey_metadata_is_available_at_initialized(const atclient_atkey_metadata *metadata) {
  return is_available_at_initialized(metadata);
}

bool atclient_atkey_metadata_is_expires_at_initialized(const atclient_atkey_metadata *metadata) {
  return is_expires_at_initialized(metadata);
}

bool atclient_atkey_metadata_is_refresh_at_initialized(const atclient_atkey_metadata *metadata) {
  return is_refresh_at_initialized(metadata);
}

bool atclient_atkey_metadata_is_created_at_initialized(const atclient_atkey_metadata *metadata) {
  return is_created_at_initialized(metadata);
}

bool atclient_atkey_metadata_is_updated_at_initialized(const atclient_atkey_metadata *metadata) {
  return is_updated_at_initialized(metadata);
}

bool atclient_atkey_metadata_is_is_public_initialized(const atclient_atkey_metadata *metadata) {
  return is_is_public_initialized(metadata);
}

bool atclient_atkey_metadata_is_is_cached_initialized(const atclient_atkey_metadata *metadata) {
  return is_is_cached_initialized(metadata);
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

bool atclient_atkey_metadata_is_is_binary_initialized(const atclient_atkey_metadata *metadata) {
  return is_is_binary_initialized(metadata);
}

bool atclient_atkey_metadata_is_is_encrypted_initialized(const atclient_atkey_metadata *metadata) {
  return is_is_encrypted_initialized(metadata);
}

bool atclient_atkey_metadata_is_data_signature_initialized(const atclient_atkey_metadata *metadata) {
  return is_data_signature_initialized(metadata);
}

bool atclient_atkey_metadata_is_shared_key_status_initialized(const atclient_atkey_metadata *metadata) {
  return is_shared_key_status_initialized(metadata);
}

bool atclient_atkey_metadata_is_shared_key_enc_initialized(const atclient_atkey_metadata *metadata) {
  return is_shared_key_enc_initialized(metadata);
}

bool atclient_atkey_metadata_is_pub_key_hash_initialized(const atclient_atkey_metadata *metadata) {
  return is_pub_key_hash_initialized(metadata);
}

bool atclient_atkey_metadata_is_pub_key_algo_initialized(const atclient_atkey_metadata *metadata) {
  return is_pub_key_algo_initialized(metadata);
}

bool atclient_atkey_metadata_is_encoding_initialized(const atclient_atkey_metadata *metadata) {
  return is_encoding_initialized(metadata);
}

bool atclient_atkey_metadata_is_enc_key_name_initialized(const atclient_atkey_metadata *metadata) {
  return is_enc_key_name_initialized(metadata);
}

bool atclient_atkey_metadata_is_enc_algo_initialized(const atclient_atkey_metadata *metadata) {
  return is_enc_algo_initialized(metadata);
}

bool atclient_atkey_metadata_is_iv_nonce_initialized(const atclient_atkey_metadata *metadata) {
  return is_iv_nonce_initialized(metadata);
}

bool atclient_atkey_metadata_is_ske_enc_key_name_initialized(const atclient_atkey_metadata *metadata) {
  return is_ske_enc_key_name_initialized(metadata);
}

bool atclient_atkey_metadata_is_ske_enc_algo_initialized(const atclient_atkey_metadata *metadata) {
  return is_ske_enc_algo_initialized(metadata);
}

int atclient_atkey_metadata_set_is_public(atclient_atkey_metadata *metadata, const bool is_public) {
  if (is_is_public_initialized(metadata)) {
    unset_is_public(metadata);
  }
  set_is_public(metadata, is_public);
  return 0;
}

int atclient_atkey_metadata_set_is_cached(atclient_atkey_metadata *metadata, const bool is_cached) {
  if (is_is_cached_initialized(metadata)) {
    unset_is_cached(metadata);
  }
  set_is_cached(metadata, is_cached);
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

int atclient_atkey_metadata_set_is_binary(atclient_atkey_metadata *metadata, const bool is_binary) {
  if (is_is_binary_initialized(metadata)) {
    unset_is_binary(metadata);
  }
  set_is_binary(metadata, is_binary);
  return 0;
}

int atclient_atkey_metadata_set_is_encrypted(atclient_atkey_metadata *metadata, const bool is_encrypted) {
  if (is_is_encrypted_initialized(metadata)) {
    unset_is_encrypted(metadata);
  }
  set_is_encrypted(metadata, is_encrypted);
  return 0;
}

int atclient_atkey_metadata_set_data_signature(atclient_atkey_metadata *metadata, const char *data_signature) {
  int ret = 1;
  if (is_data_signature_initialized(metadata)) {
    unset_data_signature(metadata);
  }
  if ((ret = set_data_signature(metadata, data_signature)) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "set_data_signature failed\n");
    goto exit;
  }
  ret = 0;
  goto exit;
exit: { return ret; }
}

int atclient_atkey_metadata_set_shared_key_status(atclient_atkey_metadata *metadata, const char *shared_key_status) {
  int ret = 1;
  if (is_shared_key_status_initialized(metadata)) {
    unset_shared_key_status(metadata);
  }
  if ((ret = set_shared_key_status(metadata, shared_key_status)) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "set_shared_key_status failed\n");
    goto exit;
  }
  ret = 0;
  goto exit;
exit: { return ret; }
}

int atclient_atkey_metadata_set_shared_key_enc(atclient_atkey_metadata *metadata, const char *shared_key_enc) {
  int ret = 1;
  if (is_shared_key_enc_initialized(metadata)) {
    unset_shared_key_enc(metadata);
  }
  if ((ret = set_shared_key_enc(metadata, shared_key_enc)) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "set_shared_key_enc failed\n");
    goto exit;
  }
  ret = 0;
  goto exit;
exit: { return ret; }
}

int atclient_atkey_metadata_set_pub_key_hash(atclient_atkey_metadata *metadata, const char *pub_key_hash) {
  int ret = 1;
  if (is_pub_key_hash_initialized(metadata)) {
    unset_pub_key_hash(metadata);
  }
  if ((ret = set_pub_key_hash(metadata, pub_key_hash)) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "set_pub_key_hash failed\n");
    goto exit;
  }
  ret = 0;
  goto exit;
exit: { return ret; }
}

int atclient_atkey_metadata_set_pub_key_algo(atclient_atkey_metadata *metadata, const char *pub_key_algo) {
  int ret = 1;
  if (is_pub_key_algo_initialized(metadata)) {
    unset_pub_key_algo(metadata);
  }
  if ((ret = set_pubkeyalgo(metadata, pub_key_algo)) != 0) {
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

int atclient_atkey_metadata_set_enc_key_name(atclient_atkey_metadata *metadata, const char *enc_key_name) {
  int ret = 1;
  if (is_enc_key_name_initialized(metadata)) {
    unset_enc_key_name(metadata);
  }
  if ((ret = set_enc_key_name(metadata, enc_key_name)) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "set_enc_key_name failed\n");
    goto exit;
  }
  ret = 0;
  goto exit;
exit: { return ret; }
}

int atclient_atkey_metadata_set_enc_algo(atclient_atkey_metadata *metadata, const char *enc_algo) {
  int ret = 1;
  if (is_enc_algo_initialized(metadata)) {
    unset_enc_algo(metadata);
  }
  if ((ret = set_enc_algo(metadata, enc_algo)) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "set_enc_algo failed\n");
    goto exit;
  }
  ret = 0;
  goto exit;
exit: { return ret; }
}

int atclient_atkey_metadata_set_iv_nonce(atclient_atkey_metadata *metadata, const char *iv_nonce) {
  int ret = 1;
  if (is_iv_nonce_initialized(metadata)) {
    unset_iv_nonce(metadata);
  }
  if ((ret = set_iv_nonce(metadata, iv_nonce)) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "set_iv_nonce failed\n");
    goto exit;
  }
  ret = 0;
  goto exit;
exit: { return ret; }
}

int atclient_atkey_metadata_set_ske_enc_key_name(atclient_atkey_metadata *metadata, const char *ske_enc_key_name) {
  int ret = 1;
  if (is_ske_enc_key_name_initialized(metadata)) {
    unset_ske_enc_key_name(metadata);
  }
  if ((ret = set_ske_enc_key_name(metadata, ske_enc_key_name)) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "set_ske_enc_key_name failed\n");
    goto exit;
  }
  ret = 0;
  goto exit;
exit: { return ret; }
}

int atclient_atkey_metadata_set_ske_enc_algo(atclient_atkey_metadata *metadata, const char *ske_enc_algo) {
  int ret = 1;
  if (is_ske_enc_algo_initialized(metadata)) {
    unset_ske_enc_algo(metadata);
  }
  if ((ret = set_ske_enc_algo(metadata, ske_enc_algo)) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "set_ske_enc_algo failed\n");
    goto exit;
  }
  ret = 0;
  goto exit;
exit: { return ret; }
}

void atclient_atkey_metadata_free(atclient_atkey_metadata *metadata) {
  unset_created_by(metadata);
  unset_updated_by(metadata);
  unset_status(metadata);
  unset_version(metadata);
  unset_expires_at(metadata);
  unset_available_at(metadata);
  unset_refresh_at(metadata);
  unset_created_at(metadata);
  unset_updated_at(metadata);
  unset_is_public(metadata);
  unset_is_cached(metadata);
  unset_ttl(metadata);
  unset_ttb(metadata);
  unset_ttr(metadata);
  unset_ccd(metadata);
  unset_is_binary(metadata);
  unset_is_encrypted(metadata);
  unset_data_signature(metadata);
  unset_shared_key_status(metadata);
  unset_shared_key_enc(metadata);
  unset_pub_key_hash(metadata);
  unset_pub_key_algo(metadata);
  unset_encoding(metadata);
  unset_enc_key_name(metadata);
  unset_enc_algo(metadata);
  unset_iv_nonce(metadata);
  unset_ske_enc_key_name(metadata);
  unset_ske_enc_algo(metadata);
  memset(metadata, 0, sizeof(atclient_atkey_metadata));
}

static bool is_created_by_initialized(const atclient_atkey_metadata *metadata) {
  return (metadata->_initialized_fields[ATCLIENT_ATKEY_METADATA_CREATEDBY_INDEX] &
          ATCLIENT_ATKEY_METADATA_CREATEDBY_INITIALIZED);
}

static bool is_updated_by_initialized(const atclient_atkey_metadata *metadata) {
  return (metadata->_initialized_fields[ATCLIENT_ATKEY_METADATA_UPDATEDBY_INDEX] &
          ATCLIENT_ATKEY_METADATA_UPDATEDBY_INITIALIZED);
}

static bool is_status_initialized(const atclient_atkey_metadata *metadata) {
  return (metadata->_initialized_fields[ATCLIENT_ATKEY_METADATA_STATUS_INDEX] &
          ATCLIENT_ATKEY_METADATA_STATUS_INITIALIZED);
}

static bool is_version_initialized(const atclient_atkey_metadata *metadata) {
  return (metadata->_initialized_fields[ATCLIENT_ATKEY_METADATA_VERSION_INDEX] &
          ATCLIENT_ATKEY_METADATA_VERSION_INITIALIZED);
}

static bool is_expires_at_initialized(const atclient_atkey_metadata *metadata) {
  return (metadata->_initialized_fields[ATCLIENT_ATKEY_METADATA_EXPIRESAT_INDEX] &
          ATCLIENT_ATKEY_METADATA_EXPIRESAT_INITIALIZED);
}

static bool is_available_at_initialized(const atclient_atkey_metadata *metadata) {
  return (metadata->_initialized_fields[ATCLIENT_ATKEY_METADATA_AVAILABLEAT_INDEX] &
          ATCLIENT_ATKEY_METADATA_AVAILABLEAT_INITIALIZED);
}

static bool is_refresh_at_initialized(const atclient_atkey_metadata *metadata) {
  return (metadata->_initialized_fields[ATCLIENT_ATKEY_METADATA_REFRESHAT_INDEX] &
          ATCLIENT_ATKEY_METADATA_REFRESHAT_INITIALIZED);
}

static bool is_created_at_initialized(const atclient_atkey_metadata *metadata) {
  return (metadata->_initialized_fields[ATCLIENT_ATKEY_METADATA_CREATEDAT_INDEX] &
          ATCLIENT_ATKEY_METADATA_CREATEDAT_INITIALIZED);
}

static bool is_updated_at_initialized(const atclient_atkey_metadata *metadata) {
  return (metadata->_initialized_fields[ATCLIENT_ATKEY_METADATA_UPDATEDAT_INDEX] &
          ATCLIENT_ATKEY_METADATA_UPDATEDAT_INITIALIZED);
}

static bool is_is_public_initialized(const atclient_atkey_metadata *metadata) {
  return (metadata->_initialized_fields[ATCLIENT_ATKEY_METADATA_ISPUBLIC_INDEX] &
          ATCLIENT_ATKEY_METADATA_ISPUBLIC_INITIALIZED);
}

static bool is_is_cached_initialized(const atclient_atkey_metadata *metadata) {
  return (metadata->_initialized_fields[ATCLIENT_ATKEY_METADATA_ISCACHED_INDEX] &
          ATCLIENT_ATKEY_METADATA_ISCACHED_INITIALIZED);
}

static bool is_ttl_initialized(const atclient_atkey_metadata *metadata) {
  return (metadata->_initialized_fields[ATCLIENT_ATKEY_METADATA_TTL_INDEX] & ATCLIENT_ATKEY_METADATA_TTL_INITIALIZED);
}

static bool is_ttb_initialized(const atclient_atkey_metadata *metadata) {
  return (metadata->_initialized_fields[ATCLIENT_ATKEY_METADATA_TTB_INDEX] & ATCLIENT_ATKEY_METADATA_TTB_INITIALIZED);
}

static bool is_ttr_initialized(const atclient_atkey_metadata *metadata) {
  return (metadata->_initialized_fields[ATCLIENT_ATKEY_METADATA_TTR_INDEX] & ATCLIENT_ATKEY_METADATA_TTR_INITIALIZED);
}

static bool is_ccd_initialized(const atclient_atkey_metadata *metadata) {
  return (metadata->_initialized_fields[ATCLIENT_ATKEY_METADATA_CCD_INDEX] & ATCLIENT_ATKEY_METADATA_CCD_INITIALIZED);
}

static bool is_is_binary_initialized(const atclient_atkey_metadata *metadata) {
  return (metadata->_initialized_fields[ATCLIENT_ATKEY_METADATA_ISBINARY_INDEX] &
          ATCLIENT_ATKEY_METADATA_ISBINARY_INITIALIZED);
}

static bool is_is_encrypted_initialized(const atclient_atkey_metadata *metadata) {
  return (metadata->_initialized_fields[ATCLIENT_ATKEY_METADATA_ISENCRYPTED_INDEX] &
          ATCLIENT_ATKEY_METADATA_ISENCRYPTED_INITIALIZED);
}

static bool is_data_signature_initialized(const atclient_atkey_metadata *metadata) {
  return (metadata->_initialized_fields[ATCLIENT_ATKEY_METADATA_DATASIGNATURE_INDEX] &
          ATCLIENT_ATKEY_METADATA_DATASIGNATURE_INITIALIZED);
}

static bool is_shared_key_status_initialized(const atclient_atkey_metadata *metadata) {
  return (metadata->_initialized_fields[ATCLIENT_ATKEY_METADATA_SHAREDKEYSTATUS_INDEX] &
          ATCLIENT_ATKEY_METADATA_SHAREDKEYSTATUS_INITIALIZED);
}

static bool is_shared_key_enc_initialized(const atclient_atkey_metadata *metadata) {
  return (metadata->_initialized_fields[ATCLIENT_ATKEY_METADATA_SHAREDKEYENC_INDEX] &
          ATCLIENT_ATKEY_METADATA_SHAREDKEYENC_INITIALIZED);
}

static bool is_pub_key_hash_initialized(const atclient_atkey_metadata *metadata) {
  return (metadata->_initialized_fields[ATCLIENT_ATKEY_METADATA_PUBKEYHASH_INDEX] &
          ATCLIENT_ATKEY_METADATA_PUBKEYHASH_INITIALIZED);
}

static bool is_pub_key_algo_initialized(const atclient_atkey_metadata *metadata) {
  return (metadata->_initialized_fields[ATCLIENT_ATKEY_METADATA_PUBKEYALGO_INDEX] &
          ATCLIENT_ATKEY_METADATA_PUBKEYALGO_INITIALIZED);
}

static bool is_encoding_initialized(const atclient_atkey_metadata *metadata) {
  return (metadata->_initialized_fields[ATCLIENT_ATKEY_METADATA_ENCODING_INDEX] &
          ATCLIENT_ATKEY_METADATA_ENCODING_INITIALIZED);
}

static bool is_enc_key_name_initialized(const atclient_atkey_metadata *metadata) {
  return (metadata->_initialized_fields[ATCLIENT_ATKEY_METADATA_ENCKEYNAME_INDEX] &
          ATCLIENT_ATKEY_METADATA_ENCKEYNAME_INITIALIZED);
}

static bool is_enc_algo_initialized(const atclient_atkey_metadata *metadata) {
  return (metadata->_initialized_fields[ATCLIENT_ATKEY_METADATA_ENCALGO_INDEX] &
          ATCLIENT_ATKEY_METADATA_ENCALGO_INITIALIZED);
}

static bool is_iv_nonce_initialized(const atclient_atkey_metadata *metadata) {
  return (metadata->_initialized_fields[ATCLIENT_ATKEY_METADATA_IVNONCE_INDEX] &
          ATCLIENT_ATKEY_METADATA_IVNONCE_INITIALIZED);
}

static bool is_ske_enc_key_name_initialized(const atclient_atkey_metadata *metadata) {
  return (metadata->_initialized_fields[ATCLIENT_ATKEY_METADATA_SKEENCKEYNAME_INDEX] &
          ATCLIENT_ATKEY_METADATA_SKEENCKEYNAME_INITIALIZED);
}

static bool is_ske_enc_algo_initialized(const atclient_atkey_metadata *metadata) {
  return (metadata->_initialized_fields[ATCLIENT_ATKEY_METADATA_SKEENCALGO_INDEX] &
          ATCLIENT_ATKEY_METADATA_SKEENCALGO_INITIALIZED);
}

static void set_is_created_by_initialized(atclient_atkey_metadata *metadata, bool is_initialized) {
  if (is_initialized) {
    metadata->_initialized_fields[ATCLIENT_ATKEY_METADATA_CREATEDBY_INDEX] |=
        ATCLIENT_ATKEY_METADATA_CREATEDBY_INITIALIZED;
  } else {
    metadata->_initialized_fields[ATCLIENT_ATKEY_METADATA_CREATEDBY_INDEX] &=
        ~ATCLIENT_ATKEY_METADATA_CREATEDBY_INITIALIZED;
  }
}

static void set_is_updated_by_initialized(atclient_atkey_metadata *metadata, bool is_initialized) {
  if (is_initialized) {
    metadata->_initialized_fields[ATCLIENT_ATKEY_METADATA_UPDATEDBY_INDEX] |=
        ATCLIENT_ATKEY_METADATA_UPDATEDBY_INITIALIZED;
  } else {
    metadata->_initialized_fields[ATCLIENT_ATKEY_METADATA_UPDATEDBY_INDEX] &=
        ~ATCLIENT_ATKEY_METADATA_UPDATEDBY_INITIALIZED;
  }
}

static void set_is_status_initialized(atclient_atkey_metadata *metadata, bool is_initialized) {
  if (is_initialized) {
    metadata->_initialized_fields[ATCLIENT_ATKEY_METADATA_STATUS_INDEX] |= ATCLIENT_ATKEY_METADATA_STATUS_INITIALIZED;
  } else {
    metadata->_initialized_fields[ATCLIENT_ATKEY_METADATA_STATUS_INDEX] &= ~ATCLIENT_ATKEY_METADATA_STATUS_INITIALIZED;
  }
}

static void set_is_version_initialized(atclient_atkey_metadata *metadata, bool is_initialized) {
  if (is_initialized) {
    metadata->_initialized_fields[ATCLIENT_ATKEY_METADATA_VERSION_INDEX] |= ATCLIENT_ATKEY_METADATA_VERSION_INITIALIZED;
  } else {
    metadata->_initialized_fields[ATCLIENT_ATKEY_METADATA_VERSION_INDEX] &=
        ~ATCLIENT_ATKEY_METADATA_VERSION_INITIALIZED;
  }
}

static void set_is_expires_at_initialized(atclient_atkey_metadata *metadata, bool is_initialized) {
  if (is_initialized) {
    metadata->_initialized_fields[ATCLIENT_ATKEY_METADATA_EXPIRESAT_INDEX] |=
        ATCLIENT_ATKEY_METADATA_EXPIRESAT_INITIALIZED;
  } else {
    metadata->_initialized_fields[ATCLIENT_ATKEY_METADATA_EXPIRESAT_INDEX] &=
        ~ATCLIENT_ATKEY_METADATA_EXPIRESAT_INITIALIZED;
  }
}

static void set_is_available_at_initialized(atclient_atkey_metadata *metadata, bool is_initialized) {
  if (is_initialized) {
    metadata->_initialized_fields[ATCLIENT_ATKEY_METADATA_AVAILABLEAT_INDEX] |=
        ATCLIENT_ATKEY_METADATA_AVAILABLEAT_INITIALIZED;
  } else {
    metadata->_initialized_fields[ATCLIENT_ATKEY_METADATA_AVAILABLEAT_INDEX] &=
        ~ATCLIENT_ATKEY_METADATA_AVAILABLEAT_INITIALIZED;
  }
}

static void set_is_refresh_at_initialized(atclient_atkey_metadata *metadata, bool is_initialized) {
  if (is_initialized) {
    metadata->_initialized_fields[ATCLIENT_ATKEY_METADATA_REFRESHAT_INDEX] |=
        ATCLIENT_ATKEY_METADATA_REFRESHAT_INITIALIZED;
  } else {
    metadata->_initialized_fields[ATCLIENT_ATKEY_METADATA_REFRESHAT_INDEX] &=
        ~ATCLIENT_ATKEY_METADATA_REFRESHAT_INITIALIZED;
  }
}

static void set_is_created_at_initialized(atclient_atkey_metadata *metadata, bool is_initialized) {
  if (is_initialized) {
    metadata->_initialized_fields[ATCLIENT_ATKEY_METADATA_CREATEDAT_INDEX] |=
        ATCLIENT_ATKEY_METADATA_CREATEDAT_INITIALIZED;
  } else {
    metadata->_initialized_fields[ATCLIENT_ATKEY_METADATA_CREATEDAT_INDEX] &=
        ~ATCLIENT_ATKEY_METADATA_CREATEDAT_INITIALIZED;
  }
}

static void set_is_updated_at_initialized(atclient_atkey_metadata *metadata, bool is_initialized) {
  if (is_initialized) {
    metadata->_initialized_fields[ATCLIENT_ATKEY_METADATA_UPDATEDAT_INDEX] |=
        ATCLIENT_ATKEY_METADATA_UPDATEDAT_INITIALIZED;
  } else {
    metadata->_initialized_fields[ATCLIENT_ATKEY_METADATA_UPDATEDAT_INDEX] &=
        ~ATCLIENT_ATKEY_METADATA_UPDATEDAT_INITIALIZED;
  }
}

static void set_is_is_public_initialized(atclient_atkey_metadata *metadata, bool is_initialized) {
  if (is_initialized) {
    metadata->_initialized_fields[ATCLIENT_ATKEY_METADATA_ISPUBLIC_INDEX] |=
        ATCLIENT_ATKEY_METADATA_ISPUBLIC_INITIALIZED;
  } else {
    metadata->_initialized_fields[ATCLIENT_ATKEY_METADATA_ISPUBLIC_INDEX] &=
        ~ATCLIENT_ATKEY_METADATA_ISPUBLIC_INITIALIZED;
  }
}

static void set_is_is_cached_initialized(atclient_atkey_metadata *metadata, bool is_initialized) {
  if (is_initialized) {
    metadata->_initialized_fields[ATCLIENT_ATKEY_METADATA_ISCACHED_INDEX] |=
        ATCLIENT_ATKEY_METADATA_ISCACHED_INITIALIZED;
  } else {
    metadata->_initialized_fields[ATCLIENT_ATKEY_METADATA_ISCACHED_INDEX] &=
        ~ATCLIENT_ATKEY_METADATA_ISCACHED_INITIALIZED;
  }
}

static void set_is_ttl_initialized(atclient_atkey_metadata *metadata, bool is_initialized) {
  if (is_initialized) {
    metadata->_initialized_fields[ATCLIENT_ATKEY_METADATA_TTL_INDEX] |= ATCLIENT_ATKEY_METADATA_TTL_INITIALIZED;
  } else {
    metadata->_initialized_fields[ATCLIENT_ATKEY_METADATA_TTL_INDEX] &= ~ATCLIENT_ATKEY_METADATA_TTL_INITIALIZED;
  }
}

static void set_is_ttb_initialized(atclient_atkey_metadata *metadata, bool is_initialized) {
  if (is_initialized) {
    metadata->_initialized_fields[ATCLIENT_ATKEY_METADATA_TTB_INDEX] |= ATCLIENT_ATKEY_METADATA_TTB_INITIALIZED;
  } else {
    metadata->_initialized_fields[ATCLIENT_ATKEY_METADATA_TTB_INDEX] &= ~ATCLIENT_ATKEY_METADATA_TTB_INITIALIZED;
  }
}

static void set_is_ttr_initialized(atclient_atkey_metadata *metadata, bool is_initialized) {
  if (is_initialized) {
    metadata->_initialized_fields[ATCLIENT_ATKEY_METADATA_TTR_INDEX] |= ATCLIENT_ATKEY_METADATA_TTR_INITIALIZED;
  } else {
    metadata->_initialized_fields[ATCLIENT_ATKEY_METADATA_TTR_INDEX] &= ~ATCLIENT_ATKEY_METADATA_TTR_INITIALIZED;
  }
}

static void set_is_ccd_initialized(atclient_atkey_metadata *metadata, bool is_initialized) {
  if (is_initialized) {
    metadata->_initialized_fields[ATCLIENT_ATKEY_METADATA_CCD_INDEX] |= ATCLIENT_ATKEY_METADATA_CCD_INITIALIZED;
  } else {
    metadata->_initialized_fields[ATCLIENT_ATKEY_METADATA_CCD_INDEX] &= ~ATCLIENT_ATKEY_METADATA_CCD_INITIALIZED;
  }
}

static void set_is_is_binary_initialized(atclient_atkey_metadata *metadata, bool is_initialized) {
  if (is_initialized) {
    metadata->_initialized_fields[ATCLIENT_ATKEY_METADATA_ISBINARY_INDEX] |=
        ATCLIENT_ATKEY_METADATA_ISBINARY_INITIALIZED;
  } else {
    metadata->_initialized_fields[ATCLIENT_ATKEY_METADATA_ISBINARY_INDEX] &=
        ~ATCLIENT_ATKEY_METADATA_ISBINARY_INITIALIZED;
  }
}

static void set_is_is_encrypted_initialized(atclient_atkey_metadata *metadata, bool is_initialized) {
  if (is_initialized) {
    metadata->_initialized_fields[ATCLIENT_ATKEY_METADATA_ISENCRYPTED_INDEX] |=
        ATCLIENT_ATKEY_METADATA_ISENCRYPTED_INITIALIZED;
  } else {
    metadata->_initialized_fields[ATCLIENT_ATKEY_METADATA_ISENCRYPTED_INDEX] &=
        ~ATCLIENT_ATKEY_METADATA_ISENCRYPTED_INITIALIZED;
  }
}

static void set_is_data_signature_initialized(atclient_atkey_metadata *metadata, bool is_initialized) {
  if (is_initialized) {
    metadata->_initialized_fields[ATCLIENT_ATKEY_METADATA_DATASIGNATURE_INDEX] |=
        ATCLIENT_ATKEY_METADATA_DATASIGNATURE_INITIALIZED;
  } else {
    metadata->_initialized_fields[ATCLIENT_ATKEY_METADATA_DATASIGNATURE_INDEX] &=
        ~ATCLIENT_ATKEY_METADATA_DATASIGNATURE_INITIALIZED;
  }
}

static void set_is_shared_key_status_initialized(atclient_atkey_metadata *metadata, bool is_initialized) {
  if (is_initialized) {
    metadata->_initialized_fields[ATCLIENT_ATKEY_METADATA_SHAREDKEYSTATUS_INDEX] |=
        ATCLIENT_ATKEY_METADATA_SHAREDKEYSTATUS_INITIALIZED;
  } else {
    metadata->_initialized_fields[ATCLIENT_ATKEY_METADATA_SHAREDKEYSTATUS_INDEX] &=
        ~ATCLIENT_ATKEY_METADATA_SHAREDKEYSTATUS_INITIALIZED;
  }
}

static void set_is_shared_key_enc_initialized(atclient_atkey_metadata *metadata, bool is_initialized) {
  if (is_initialized) {
    metadata->_initialized_fields[ATCLIENT_ATKEY_METADATA_SHAREDKEYENC_INDEX] |=
        ATCLIENT_ATKEY_METADATA_SHAREDKEYENC_INITIALIZED;
  } else {
    metadata->_initialized_fields[ATCLIENT_ATKEY_METADATA_SHAREDKEYENC_INDEX] &=
        ~ATCLIENT_ATKEY_METADATA_SHAREDKEYENC_INITIALIZED;
  }
}

static void set_is_pub_key_hash_initialized(atclient_atkey_metadata *metadata, bool is_initialized) {
  if (is_initialized) {
    metadata->_initialized_fields[ATCLIENT_ATKEY_METADATA_PUBKEYHASH_INDEX] |=
        ATCLIENT_ATKEY_METADATA_PUBKEYHASH_INITIALIZED;
  } else {
    metadata->_initialized_fields[ATCLIENT_ATKEY_METADATA_PUBKEYHASH_INDEX] &=
        ~ATCLIENT_ATKEY_METADATA_PUBKEYHASH_INITIALIZED;
  }
}

static void set_is_pub_key_algo_initialized(atclient_atkey_metadata *metadata, bool is_initialized) {
  if (is_initialized) {
    metadata->_initialized_fields[ATCLIENT_ATKEY_METADATA_PUBKEYALGO_INDEX] |=
        ATCLIENT_ATKEY_METADATA_PUBKEYALGO_INITIALIZED;
  } else {
    metadata->_initialized_fields[ATCLIENT_ATKEY_METADATA_PUBKEYALGO_INDEX] &=
        ~ATCLIENT_ATKEY_METADATA_PUBKEYALGO_INITIALIZED;
  }
}

static void set_is_encoding_initialized(atclient_atkey_metadata *metadata, bool is_initialized) {
  if (is_initialized) {
    metadata->_initialized_fields[ATCLIENT_ATKEY_METADATA_ENCODING_INDEX] |=
        ATCLIENT_ATKEY_METADATA_ENCODING_INITIALIZED;
  } else {
    metadata->_initialized_fields[ATCLIENT_ATKEY_METADATA_ENCODING_INDEX] &=
        ~ATCLIENT_ATKEY_METADATA_ENCODING_INITIALIZED;
  }
}

static void set_is_enc_key_name_initialized(atclient_atkey_metadata *metadata, bool is_initialized) {
  if (is_initialized) {
    metadata->_initialized_fields[ATCLIENT_ATKEY_METADATA_ENCKEYNAME_INDEX] |=
        ATCLIENT_ATKEY_METADATA_ENCKEYNAME_INITIALIZED;
  } else {
    metadata->_initialized_fields[ATCLIENT_ATKEY_METADATA_ENCKEYNAME_INDEX] &=
        ~ATCLIENT_ATKEY_METADATA_ENCKEYNAME_INITIALIZED;
  }
}

static void set_is_enc_algo_initialized(atclient_atkey_metadata *metadata, bool is_initialized) {
  if (is_initialized) {
    metadata->_initialized_fields[ATCLIENT_ATKEY_METADATA_ENCALGO_INDEX] |= ATCLIENT_ATKEY_METADATA_ENCALGO_INITIALIZED;
  } else {
    metadata->_initialized_fields[ATCLIENT_ATKEY_METADATA_ENCALGO_INDEX] &=
        ~ATCLIENT_ATKEY_METADATA_ENCALGO_INITIALIZED;
  }
}

static void set_is_iv_nonce_initialized(atclient_atkey_metadata *metadata, bool is_initialized) {
  if (is_initialized) {
    metadata->_initialized_fields[ATCLIENT_ATKEY_METADATA_IVNONCE_INDEX] |= ATCLIENT_ATKEY_METADATA_IVNONCE_INITIALIZED;
  } else {
    metadata->_initialized_fields[ATCLIENT_ATKEY_METADATA_IVNONCE_INDEX] &=
        ~ATCLIENT_ATKEY_METADATA_IVNONCE_INITIALIZED;
  }
}

static void set_is_ske_enc_key_name_initialized(atclient_atkey_metadata *metadata, bool is_initialized) {
  if (is_initialized) {
    metadata->_initialized_fields[ATCLIENT_ATKEY_METADATA_SKEENCKEYNAME_INDEX] |=
        ATCLIENT_ATKEY_METADATA_SKEENCKEYNAME_INITIALIZED;
  } else {
    metadata->_initialized_fields[ATCLIENT_ATKEY_METADATA_SKEENCKEYNAME_INDEX] &=
        ~ATCLIENT_ATKEY_METADATA_SKEENCKEYNAME_INITIALIZED;
  }
}

static void set_is_ske_enc_algo_initialized(atclient_atkey_metadata *metadata, bool is_initialized) {
  if (is_initialized) {
    metadata->_initialized_fields[ATCLIENT_ATKEY_METADATA_SKEENCALGO_INDEX] |=
        ATCLIENT_ATKEY_METADATA_SKEENCALGO_INITIALIZED;
  } else {
    metadata->_initialized_fields[ATCLIENT_ATKEY_METADATA_SKEENCALGO_INDEX] &=
        ~ATCLIENT_ATKEY_METADATA_SKEENCALGO_INITIALIZED;
  }
}

static void unset_created_by(atclient_atkey_metadata *metadata) {
  if (is_created_by_initialized(metadata)) {
    free(metadata->created_by);
  }
  metadata->created_by = NULL;
  set_is_created_by_initialized(metadata, false);
}

static void unset_updated_by(atclient_atkey_metadata *metadata) {
  if (is_updated_by_initialized(metadata)) {
    free(metadata->updated_by);
  }
  metadata->updated_by = NULL;
  set_is_updated_by_initialized(metadata, false);
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

static void unset_expires_at(atclient_atkey_metadata *metadata) {
  if (is_expires_at_initialized(metadata)) {
    free(metadata->expires_at);
  }
  metadata->expires_at = NULL;
  set_is_expires_at_initialized(metadata, false);
}

static void unset_available_at(atclient_atkey_metadata *metadata) {
  if (is_available_at_initialized(metadata)) {
    free(metadata->available_at);
  }
  metadata->available_at = NULL;
  set_is_available_at_initialized(metadata, false);
}

static void unset_refresh_at(atclient_atkey_metadata *metadata) {
  if (is_refresh_at_initialized(metadata)) {
    free(metadata->refresh_at);
  }
  metadata->refresh_at = NULL;
  set_is_refresh_at_initialized(metadata, false);
}

static void unset_created_at(atclient_atkey_metadata *metadata) {
  if (is_created_at_initialized(metadata)) {
    free(metadata->created_at);
  }
  metadata->created_at = NULL;
  set_is_created_at_initialized(metadata, false);
}

static void unset_updated_at(atclient_atkey_metadata *metadata) {
  if (is_updated_at_initialized(metadata)) {
    free(metadata->updated_at);
  }
  metadata->updated_at = NULL;
  set_is_updated_at_initialized(metadata, false);
}

static void unset_is_public(atclient_atkey_metadata *metadata) {
  metadata->is_public = false;
  set_is_is_public_initialized(metadata, false);
}

static void unset_is_cached(atclient_atkey_metadata *metadata) {
  metadata->is_cached = false;
  set_is_is_cached_initialized(metadata, false);
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

static void unset_is_binary(atclient_atkey_metadata *metadata) {
  metadata->is_binary = false;
  set_is_is_binary_initialized(metadata, false);
}

static void unset_is_encrypted(atclient_atkey_metadata *metadata) {
  metadata->is_encrypted = false;
  set_is_is_encrypted_initialized(metadata, false);
}

static void unset_data_signature(atclient_atkey_metadata *metadata) {
  if (is_data_signature_initialized(metadata)) {
    free(metadata->data_signature);
  }
  metadata->data_signature = NULL;
  set_is_data_signature_initialized(metadata, false);
}

static void unset_shared_key_status(atclient_atkey_metadata *metadata) {
  if (is_shared_key_status_initialized(metadata)) {
    free(metadata->shared_key_status);
  }
  metadata->shared_key_status = NULL;
  set_is_shared_key_status_initialized(metadata, false);
}

static void unset_shared_key_enc(atclient_atkey_metadata *metadata) {
  if (is_shared_key_enc_initialized(metadata)) {
    free(metadata->shared_key_enc);
  }
  metadata->shared_key_enc = NULL;
  set_is_shared_key_enc_initialized(metadata, false);
}

static void unset_pub_key_hash(atclient_atkey_metadata *metadata) {
  if (is_pub_key_hash_initialized(metadata)) {
    free(metadata->pub_key_hash);
  }
  metadata->pub_key_hash = NULL;
  set_is_pub_key_hash_initialized(metadata, false);
}

static void unset_pub_key_algo(atclient_atkey_metadata *metadata) {
  if (is_pub_key_algo_initialized(metadata)) {
    free(metadata->pub_key_algo);
  }
  metadata->pub_key_algo = NULL;
  set_is_pub_key_algo_initialized(metadata, false);
}

static void unset_encoding(atclient_atkey_metadata *metadata) {
  if (is_encoding_initialized(metadata)) {
    free(metadata->encoding);
  }
  metadata->encoding = NULL;
  set_is_encoding_initialized(metadata, false);
}

static void unset_enc_key_name(atclient_atkey_metadata *metadata) {
  if (is_enc_key_name_initialized(metadata)) {
    free(metadata->enc_key_name);
  }
  set_is_enc_key_name_initialized(metadata, false);
}

static void unset_enc_algo(atclient_atkey_metadata *metadata) {
  if (is_enc_algo_initialized(metadata)) {
    free(metadata->enc_algo);
  }
  metadata->enc_algo = NULL;
  set_is_enc_algo_initialized(metadata, false);
}

static void unset_iv_nonce(atclient_atkey_metadata *metadata) {
  if (is_iv_nonce_initialized(metadata)) {
    free(metadata->iv_nonce);
  }
  metadata->iv_nonce = NULL;
  set_is_iv_nonce_initialized(metadata, false);
}

static void unset_ske_enc_key_name(atclient_atkey_metadata *metadata) {
  if (is_ske_enc_key_name_initialized(metadata)) {
    free(metadata->ske_enc_key_name);
  }
  metadata->ske_enc_key_name = NULL;
  set_is_ske_enc_key_name_initialized(metadata, false);
}

static void unset_ske_enc_algo(atclient_atkey_metadata *metadata) {
  if (is_ske_enc_algo_initialized(metadata)) {
    free(metadata->ske_enc_algo);
  }
  metadata->ske_enc_algo = NULL;
  set_is_ske_enc_algo_initialized(metadata, false);
}

static int set_created_by(atclient_atkey_metadata *metadata, const char *created_by) {
  int ret = 1;
  const size_t created_by_len = strlen(created_by);
  const size_t created_by_size = created_by_len + 1;
  if ((metadata->created_by = malloc(sizeof(char) * (created_by_size))) == NULL) {
    ret = 1;
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "set_created_by malloc failed\n");
    goto exit;
  }
  memcpy(metadata->created_by, created_by, created_by_len);
  metadata->created_by[created_by_len] = '\0';
  set_is_created_by_initialized(metadata, true);
  ret = 0;
  goto exit;
exit: { return ret; }
}

static int set_updated_by(atclient_atkey_metadata *metadata, const char *updated_by) {
  int ret = 1;
  const size_t updated_by_len = strlen(updated_by);
  const size_t updated_by_size = updated_by_len + 1;
  if ((metadata->updated_by = malloc(sizeof(char) * (updated_by_size))) == NULL) {
    ret = 1;
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "set_updated_by malloc failed\n");
    goto exit;
  }
  memcpy(metadata->updated_by, updated_by, updated_by_len);
  metadata->updated_by[updated_by_len] = '\0';
  set_is_updated_by_initialized(metadata, true);
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

static int set_expires_at(atclient_atkey_metadata *metadata, const char *expires_at) {
  int ret = 1;
  const size_t expires_at_len = strlen(expires_at);
  const size_t expires_at_size = expires_at_len + 1;
  if ((metadata->expires_at = malloc(sizeof(char) * (expires_at_size))) == NULL) {
    ret = 1;
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "set_expires_at malloc failed\n");
    goto exit;
  }
  memcpy(metadata->expires_at, expires_at, expires_at_len);
  metadata->expires_at[expires_at_len] = '\0';
  set_is_expires_at_initialized(metadata, true);
  ret = 0;
  goto exit;
exit: { return ret; }
}

static int set_available_at(atclient_atkey_metadata *metadata, const char *available_at) {
  int ret = 1;
  const size_t available_at_len = strlen(available_at);
  const size_t available_at_size = available_at_len + 1;
  if ((metadata->available_at = malloc(sizeof(char) * (available_at_size))) == NULL) {
    ret = 1;
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "set_available_at malloc failed\n");
    goto exit;
  }
  memcpy(metadata->available_at, available_at, available_at_len);
  metadata->available_at[available_at_len] = '\0';
  set_is_available_at_initialized(metadata, true);
  ret = 0;
  goto exit;
exit: { return ret; }
}

static int set_refresh_at(atclient_atkey_metadata *metadata, const char *refresh_at) {
  int ret = 1;
  const size_t refresh_at_len = strlen(refresh_at);
  const size_t refresh_at_size = refresh_at_len + 1;
  if ((metadata->refresh_at = malloc(sizeof(char) * (refresh_at_size))) == NULL) {
    ret = 1;
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "set_refresh_at malloc failed\n");
    goto exit;
  }
  memcpy(metadata->refresh_at, refresh_at, refresh_at_len);
  metadata->refresh_at[refresh_at_len] = '\0';
  set_is_refresh_at_initialized(metadata, true);
  ret = 0;
  goto exit;
exit: { return ret; }
}

static int set_created_at(atclient_atkey_metadata *metadata, const char *created_at) {
  int ret = 1;
  const size_t created_at_len = strlen(created_at);
  const size_t created_at_size = created_at_len + 1;
  if ((metadata->created_at = malloc(sizeof(char) * (created_at_len + 1))) == NULL) {
    ret = 1;
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "set_created_at malloc failed\n");
    goto exit;
  }
  memcpy(metadata->created_at, created_at, created_at_len);
  metadata->created_at[created_at_len] = '\0';
  set_is_created_at_initialized(metadata, true);
  ret = 0;
  goto exit;
exit: { return ret; }
}

static int set_updated_at(atclient_atkey_metadata *metadata, const char *updated_at) {
  int ret = 1;
  const size_t updated_at_len = strlen(updated_at);
  const size_t updated_at_size = updated_at_len + 1;
  if ((metadata->updated_at = malloc(sizeof(char) * (updated_at_size))) == NULL) {
    ret = 1;
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "set_updated_at malloc failed\n");
    goto exit;
  }
  memcpy(metadata->updated_at, updated_at, updated_at_len);
  metadata->updated_at[updated_at_len] = '\0';
  set_is_updated_at_initialized(metadata, true);
  ret = 0;
  goto exit;
exit: { return ret; }
}

static void set_is_public(atclient_atkey_metadata *metadata, const bool is_public) {
  metadata->is_public = is_public;
  set_is_is_public_initialized(metadata, true);
}

static void set_is_cached(atclient_atkey_metadata *metadata, const bool is_cached) {
  metadata->is_cached = is_cached;
  set_is_is_cached_initialized(metadata, true);
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

static void set_is_binary(atclient_atkey_metadata *metadata, const bool is_binary) {
  metadata->is_binary = is_binary;
  set_is_is_binary_initialized(metadata, true);
}

static void set_is_encrypted(atclient_atkey_metadata *metadata, const bool is_encrypted) {
  metadata->is_encrypted = is_encrypted;
  set_is_is_encrypted_initialized(metadata, true);
}

static int set_data_signature(atclient_atkey_metadata *metadata, const char *data_signature) {
  int ret = 1;
  const size_t data_signature_len = strlen(data_signature);
  const size_t data_signature_size = data_signature_len + 1;
  if ((metadata->data_signature = malloc(sizeof(char) * (data_signature_size))) == NULL) {
    ret = 1;
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "set_data_signature malloc failed\n");
    goto exit;
  }
  memcpy(metadata->data_signature, data_signature, data_signature_len);
  metadata->data_signature[data_signature_len] = '\0';
  set_is_data_signature_initialized(metadata, true);
  ret = 0;
  goto exit;
exit: { return ret; }
}

static int set_shared_key_status(atclient_atkey_metadata *metadata, const char *shared_key_status) {
  int ret = 1;
  const size_t shared_key_status_len = strlen(shared_key_status);
  const size_t shared_key_status_size = shared_key_status_len + 1;
  if ((metadata->shared_key_status = malloc(sizeof(char) * (shared_key_status_size))) == NULL) {
    ret = 1;
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "set_shared_key_status malloc failed\n");
    goto exit;
  }
  memcpy(metadata->shared_key_status, shared_key_status, shared_key_status_len);
  metadata->shared_key_status[shared_key_status_len] = '\0';
  set_is_shared_key_status_initialized(metadata, true);
  ret = 0;
  goto exit;
exit: { return ret; }
}

static int set_shared_key_enc(atclient_atkey_metadata *metadata, const char *shared_key_enc) {
  int ret = 1;
  const size_t shared_key_enc_len = strlen(shared_key_enc);
  const size_t shared_key_enc_size = shared_key_enc_len + 1;
  if ((metadata->shared_key_enc = malloc(sizeof(char) * (shared_key_enc_size))) == NULL) {
    ret = 1;
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "set_shared_key_enc malloc failed\n");
    goto exit;
  }
  memcpy(metadata->shared_key_enc, shared_key_enc, shared_key_enc_len);
  metadata->shared_key_enc[shared_key_enc_len] = '\0';
  set_is_shared_key_enc_initialized(metadata, true);
  ret = 0;
  goto exit;
exit: { return ret; }
}

static int set_pub_key_hash(atclient_atkey_metadata *metadata, const char *pub_key_hash) {
  int ret = 1;
  const size_t pub_key_hash_len = strlen(pub_key_hash);
  const size_t pub_key_hash_size = pub_key_hash_len + 1;
  if ((metadata->pub_key_hash = malloc(sizeof(char) * (pub_key_hash_size))) == NULL) {
    ret = 1;
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "set_pub_key_hash malloc failed\n");
    goto exit;
  }
  memcpy(metadata->pub_key_hash, pub_key_hash, pub_key_hash_len);
  metadata->pub_key_hash[pub_key_hash_len] = '\0';
  set_is_pub_key_hash_initialized(metadata, true);
  ret = 0;
  goto exit;
exit: { return ret; }
}

static int set_pubkeyalgo(atclient_atkey_metadata *metadata, const char *pub_key_algo) {
  int ret = 1;
  const size_t pub_key_algo_len = strlen(pub_key_algo);
  const size_t pub_key_algo_size = pub_key_algo_len + 1;
  if ((metadata->pub_key_algo = malloc(sizeof(char) * (pub_key_algo_size))) == NULL) {
    ret = 1;
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "set_pubkeyalgo malloc failed\n");
    goto exit;
  }
  memcpy(metadata->pub_key_algo, pub_key_algo, pub_key_algo_len);
  metadata->pub_key_algo[pub_key_algo_len] = '\0';
  set_is_pub_key_algo_initialized(metadata, true);
  ret = 0;
  goto exit;
exit: { return ret; }
}

static int set_encoding(atclient_atkey_metadata *metadata, const char *encoding) {
  int ret = 1;
  const size_t encoding_len = strlen(encoding);
  const size_t encoding_size = encoding_len + 1;
  if ((metadata->encoding = malloc(sizeof(char) * (encoding_size))) == NULL) {
    ret = 1;
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "set_encoding malloc failed\n");
    goto exit;
  }
  memcpy(metadata->encoding, encoding, encoding_len);
  metadata->encoding[encoding_len] = '\0';
  set_is_encoding_initialized(metadata, true);
  ret = 0;
  goto exit;
exit: { return ret; }
}

static int set_enc_key_name(atclient_atkey_metadata *metadata, const char *enc_key_name) {
  int ret = 1;
  const size_t enc_key_name_len = strlen(enc_key_name);
  const size_t enc_key_name_size = enc_key_name_len + 1;
  if ((metadata->enc_key_name = malloc(sizeof(char) * (enc_key_name_size))) == NULL) {
    ret = 1;
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "set_enc_key_name malloc failed\n");
    goto exit;
  }
  memcpy(metadata->enc_key_name, enc_key_name, enc_key_name_len);
  metadata->enc_key_name[enc_key_name_len] = '\0';
  set_is_enc_key_name_initialized(metadata, true);
  ret = 0;
  goto exit;
exit: { return ret; }
}

static int set_enc_algo(atclient_atkey_metadata *metadata, const char *enc_algo) {
  int ret = 1;
  const size_t enc_algo_len = strlen(enc_algo);
  const size_t enc_algo_size = enc_algo_len + 1;
  if ((metadata->enc_algo = malloc(sizeof(char) * (enc_algo_size))) == NULL) {
    ret = 1;
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "set_enc_algo malloc failed\n");
    goto exit;
  }
  memcpy(metadata->enc_algo, enc_algo, enc_algo_len);
  metadata->enc_algo[enc_algo_len] = '\0';
  set_is_enc_algo_initialized(metadata, true);
  ret = 0;
  goto exit;
exit: { return ret; }
}

static int set_iv_nonce(atclient_atkey_metadata *metadata, const char *iv_nonce) {
  int ret = 1;
  const size_t iv_nonce_len = strlen(iv_nonce);
  const size_t iv_nonce_size = iv_nonce_len + 1;
  if ((metadata->iv_nonce = malloc(sizeof(char) * (iv_nonce_size))) == NULL) {
    ret = 1;
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "set_iv_nonce malloc failed\n");
    goto exit;
  }
  memcpy(metadata->iv_nonce, iv_nonce, iv_nonce_len);
  metadata->iv_nonce[iv_nonce_len] = '\0';
  set_is_iv_nonce_initialized(metadata, true);
  ret = 0;
  goto exit;
exit: { return ret; }
}

static int set_ske_enc_key_name(atclient_atkey_metadata *metadata, const char *ske_enc_key_name) {
  int ret = 1;
  const size_t ske_enc_key_name_len = strlen(ske_enc_key_name);
  const size_t ske_enc_key_name_size = ske_enc_key_name_len + 1;
  if ((metadata->ske_enc_key_name = malloc(sizeof(char) * (ske_enc_key_name_size))) == NULL) {
    ret = 1;
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "set_ske_enc_key_name malloc failed\n");
    goto exit;
  }
  memcpy(metadata->ske_enc_key_name, ske_enc_key_name, ske_enc_key_name_len);
  metadata->ske_enc_key_name[ske_enc_key_name_len] = '\0';
  set_is_ske_enc_key_name_initialized(metadata, true);
  ret = 0;
  goto exit;
exit: { return ret; }
}

static int set_ske_enc_algo(atclient_atkey_metadata *metadata, const char *ske_enc_algo) {
  int ret = 1;
  const size_t ske_enc_algo_len = strlen(ske_enc_algo);
  const size_t ske_enc_algo_size = ske_enc_algo_len + 1;
  if ((metadata->ske_enc_algo = malloc(sizeof(char) * (ske_enc_algo_size))) == NULL) {
    ret = 1;
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "set_ske_enc_algo malloc failed\n");
    goto exit;
  }
  memcpy(metadata->ske_enc_algo, ske_enc_algo, ske_enc_algo_len);
  metadata->ske_enc_algo[ske_enc_algo_len] = '\0';
  set_is_ske_enc_algo_initialized(metadata, true);
  ret = 0;
  goto exit;
exit: { return ret; }
}
