#include "atcommons/enroll_params.h"
#include <atlogger/atlogger.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "../../../../_deps/cjson-src/cJSON.h"

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
int enroll_params_init(enroll_params *ep) {
  /*
   * 1. Validate arguments
   */
  if (ep == NULL) {
    return -1;
  }

  /*
   * 2. Initialize
   */
  memset(ep, 0, sizeof(enroll_params));
  ep->enrollment_id = NULL;
  ep->app_name = NULL;
  ep->device_name = NULL;
  ep->otp = NULL;
  ep->apkam_public_key = NULL;
  ep->encrypted_default_encryption_private_key = NULL;
  ep->encrypted_default_self_encryption_key = NULL;
  ep->encrypted_apkam_symmetric_key = NULL;
  ep->ns_list = NULL;
}

int enroll_params_to_json(char **json_string, size_t **json_string_len, const size_t json_string_size,
                          const enroll_params *ep) {
  int ret = 0;

  if (ep == NULL) {
    ret = -1;
    return ret;
  }

  cJSON *json = cJSON_CreateObject();
  if (!json) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "Failed to create json object\n");
    ret = -1;
    return ret;
  }

  // Add each parameter to JSON only if it is not NULL
  if (ep->enrollment_id && ep->enrollment_id != NULL) {
    cJSON_AddStringToObject(json, ENROLLMENT_ID, ep->enrollment_id);
  }

  if (ep->app_name) {
    cJSON_AddStringToObject(json, APP_NAME, ep->app_name);
  }

  if (ep->device_name) {
    cJSON_AddStringToObject(json, DEVICE_NAME, ep->device_name);
  }

  if (ep->otp) {
    cJSON_AddStringToObject(json, OTP, ep->otp);
  }

  // Ensure ns_list is not NULL before accessing namespaces
  char *ns_json = NULL;
  if (ep->ns_list && ep->ns_list->namespaces[0]) {
    size_t ns_list_str_len = 0;
    atcommons_enroll_namespace_list_to_json(NULL, &ns_list_str_len, ep->ns_list); // get string length
    ns_json = malloc(sizeof(char) * ns_list_str_len + 1);                         // to be freed 1
    memset(ns_json, 0, sizeof(char) * ns_list_str_len + 1);

    if (!ns_json || (ret = atcommons_enroll_namespace_list_to_json(ns_json, &ns_list_str_len, ep->ns_list)) != 0) {
      atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR,
                   "Could not convert enroll_namepsace_list to json. atcommons_enroll_namespace_list_to_json: %d\n",
                   ret);
      cJSON_Delete(json); // Clean up the JSON object in case of an error
      ret = 1;
      goto exit;
    }
    cJSON_AddRawToObject(json, NAMESPACES, ns_json);
  }

  // Add Base64-encoded strings directly to JSON
  if (ep->apkam_public_key) {
    cJSON_AddStringToObject(json, APKAM_PUBLIC_KEY, (char *)ep->apkam_public_key);
  }

  if (ep->encrypted_default_encryption_private_key) {
    cJSON_AddStringToObject(json, ENCRYPTED_DEFAULT_ENCRYPTION_PRIVATE_KEY,
                            (char *)ep->encrypted_default_encryption_private_key);
  }

  if (ep->encrypted_default_self_encryption_key) {
    cJSON_AddStringToObject(json, ENCRYPTED_DEFAULT_SELF_ENCRYPTION_KEY,
                            (char *)ep->encrypted_default_self_encryption_key);
  }

  if (ep->encrypted_apkam_symmetric_key) {
    cJSON_AddStringToObject(json, ENCRYPTED_APKAM_SYMMETRIC_KEY, (char *)ep->encrypted_apkam_symmetric_key);
  }

  if (json_string_len == NULL) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "json_string_len cannot be NULL");
    ret = -1;
    goto exit;
  }

  if (json_string == NULL) { // only populate 'json_string_len' when 'json_string' is NULL
    *json_string_len = snprintf(NULL, 0, cJSON_PrintUnformatted(json));
    ret = 1; // returing not-zero exit code to ensure method cannot be used without 'json_string'
    goto exit;
  }

  *json_string_len = snprintf(*json_string, json_string_size, cJSON_PrintUnformatted(json));

exit: {
  cJSON_Delete(json);
  // if(ns_json) free(ns_json); // freed 1
  return ret;
}
}
