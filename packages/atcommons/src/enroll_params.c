#include "atcommons/enroll_params.h"

#include "atcommons/json.h"

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

int atcommons_enroll_params_init(atcommons_enroll_params_t *ep) {
  /*
   * 1. Validate arguments
   */
  if (ep == NULL) {
    return -1;
  }

  /*
   * 2. Initialize
   */
  memset(ep, 0, sizeof(atcommons_enroll_params_t));

  return 0;
}

#ifdef ATCOMMONS_JSON_PROVIDER_CJSON
int atcommons_enroll_params_to_json(char **json_string, size_t *json_string_len, const atcommons_enroll_params_t *ep) {
  int ret = 0;

  if (ep == NULL) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR,
                 "enroll params cannot be null for atcommons_enroll_params_to_json\n");
    ret = -1;
    return ret;
  }

  cJSON *json_object = cJSON_CreateObject();
  if (json_object == NULL) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "Failed to create JSON object\n");
    ret = -1;
    return ret;
  }

  // Add each parameter to JSON only if it is not NULL
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

  char *ns_json = NULL;
  // Ensure ns_list is not NULL before accessing namespaces
  if (ep->ns_list != NULL && ep->ns_list->length > 0) {
    size_t ns_list_str_len = 0;
    if ((ret = atcommons_enroll_namespace_list_to_json(&ns_json, &ns_list_str_len, ep->ns_list)) != 0) {
      atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR,
                   "enroll_namespace_list serialization failed. atcommons_enroll_namespace_list_to_json: %d\n", ret);
      ret = 1;
      goto exit;
    }
    cJSON_AddRawToObject(json_object, NAMESPACES, ns_json);
  }

  // Add Base64-encoded strings directly to JSON
  if (ep->apkam_public_key != NULL) {
    cJSON_AddStringToObject(json_object, APKAM_PUBLIC_KEY, (const char *)ep->apkam_public_key);
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
  // pass memory ownership of the json string to the caller
  if (json_string != NULL) {
    *json_string = cJSON_PrintUnformatted(json_object);
  }
  if (json_string_len != NULL) {
    *json_string_len = strlen(cJSON_PrintUnformatted(json_object));
  }

exit:
  free(ns_json);
  cJSON_Delete(json_object);
  return ret;
}
#else
#error "JSON provider not supported"
#endif
