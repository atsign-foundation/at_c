#include "enroll_params.h"

#include "atclient/json.h"
#include "enroll_namespace.h"

#include <atlogger/atlogger.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define ENROLLMENT_ID "enrollmentId"
#define APP_NAME "appName"
#define DEVICE_NAME "deviceName"
#define OTP "otp"
#define NAMESPACES "namespaces"
#define APKAM_PUBLIC_KEY "apkamPublicKey"
#define ENCRYPTED_DEFAULT_ENCRYPTION_PRIVATE_KEY "encryptedDefaultEncryptionPrivateKey"
#define ENCRYPTED_DEFAULT_SELF_ENCRYPTION_KEY "encryptedDefaultSelfEncryptionKey"
#define ENCRYPTED_APKAM_SYMMETRIC_KEY "encryptedAPKAMSymmetricKey"
#define APKAM_KEYS_EXPIRY "apkamKeysExpiryInMillis" // in milliseconds

#define TAG "enroll_params"

void atauth_enroll_params_init(atauth_enroll_params_t *ep) {
  if (ep == NULL) {
    return;
  }
  ep->enrollment_id = NULL;
  ep->app_name = NULL;
  ep->device_name = NULL;
  ep->otp = NULL;
  ep->apkam_public_key = NULL;
  ep->encrypted_default_encryption_private_key = NULL;
  ep->encrypted_default_encryption_private_key_iv = NULL;
  ep->encrypted_self_encryption_key = NULL;
  ep->encrypted_self_encryption_key_iv = NULL;
  ep->encrypted_apkam_symmetric_key = NULL;
  ep->encrypted_apkam_symmetric_key_iv = NULL;
  ep->namespaces = NULL;
  ep->apkam_keys_expiry_in_millis = 0;
}

#ifdef ATCOMMONS_JSON_PROVIDER_CJSON
int atauth_enroll_params_to_json(const atauth_enroll_params_t *ep, char **json_string) {
  int ret = 0;

  if (ep == NULL) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "enroll params cannot be null for atauth_enroll_params_to_json\n");
    ret = -1;
    return ret;
  }

  cJSON *json_object = cJSON_CreateObject();
  if (json_object == NULL) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "Failed to create JSON object\n");
    ret = -1;
    return ret;
  }

  if (ep->enrollment_id != NULL) {
    cJSON_AddStringToObject(json_object, ENROLLMENT_ID, ep->enrollment_id);
  }

  if (ep->app_name != NULL) {
    cJSON_AddStringToObject(json_object, APP_NAME, ep->app_name);
  }

  if (ep->device_name != NULL) {
    cJSON_AddStringToObject(json_object, DEVICE_NAME, ep->device_name);
  }

  if (ep->otp != NULL) {
    cJSON_AddStringToObject(json_object, OTP, ep->otp);
  }

  if (ep->namespaces != NULL && ep->namespaces->len > 0) {
    char *ns_json = NULL;
    ret = enroll_namespace_to_json_string(ep->namespaces, &ns_json);
    if (ret != 0) {
      atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "Failed to convert namespace list to json\n");
      goto exit;
    }
    cJSON_AddRawToObject(json_object, NAMESPACES, ns_json);
    free(ns_json);
  }

  // Add Base64-encoded strings directly to JSON
  if (ep->apkam_public_key != NULL) {
    cJSON_AddStringToObject(json_object, APKAM_PUBLIC_KEY, ep->apkam_public_key);
  }

  if (ep->encrypted_default_encryption_private_key != NULL) {
    cJSON_AddStringToObject(json_object, ENCRYPTED_DEFAULT_ENCRYPTION_PRIVATE_KEY,
                            (const char *)ep->encrypted_default_encryption_private_key);
  }

  if (ep->encrypted_self_encryption_key != NULL) {
    cJSON_AddStringToObject(json_object, ENCRYPTED_DEFAULT_SELF_ENCRYPTION_KEY,
                            (const char *)ep->encrypted_self_encryption_key);
  }

  if (ep->encrypted_apkam_symmetric_key != NULL) {
    cJSON_AddStringToObject(json_object, ENCRYPTED_APKAM_SYMMETRIC_KEY,
                            (const char *)ep->encrypted_apkam_symmetric_key);
  }

  if (ep->apkam_keys_expiry_in_millis > 0) {
    cJSON_AddNumberToObject(json_object, APKAM_KEYS_EXPIRY, (double)ep->apkam_keys_expiry_in_millis);
  }
  // pass memory ownership of the json string to the caller
  if (json_string != NULL) {
    *json_string = cJSON_PrintUnformatted(json_object);
  }

exit:
  cJSON_Delete(json_object);
  return ret;
}
#else
#error "JSON provider not supported"
#endif
