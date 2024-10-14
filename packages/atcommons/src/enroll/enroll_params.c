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

int enroll_params_init(enroll_params_t *ep) {
  /*
   * 1. Validate arguments
   */
  if (ep == NULL) {
    return -1;
  }

  /*
   * 2. Initialize
   */
  memset(ep, 0, sizeof(enroll_params_t));
  ep->enrollment_id = NULL;
  ep->app_name = NULL;
  ep->device_name = NULL;
  ep->otp = NULL;
  ep->apkam_public_key = NULL;
  ep->encrypted_default_encryption_private_key = NULL;
  ep->encrypted_self_encryption_key = NULL;
  ep->encrypted_apkam_symmetric_key = NULL;
  ep->ns_list = NULL;

  return 0; // Ensure return for successful initialization
}

int enroll_params_to_json(char **json_string, size_t *json_string_len, const size_t json_string_size, const enroll_params_t *ep) {
  int ret = 0;

  if (ep == NULL) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "enroll params cannot be null for enroll_params_to_json\n");
    ret = -1;
    return ret;
  }

  cJSON *json = cJSON_CreateObject();
  if (!json) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "Failed to create JSON object\n");
    ret = -1;
    return ret;
  }

  // Add each parameter to JSON only if it is not NULL
  if (ep->enrollment_id) {
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
  if (ep->ns_list && ep->ns_list->length > 0) {
    size_t ns_list_str_len = 0;
    atcommons_enroll_namespace_list_to_json(NULL, &ns_list_str_len, ep->ns_list); // get string length
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_DEBUG, "enroll_namespace_list_to_string len is %lu\n", ns_list_str_len);
    ns_json = malloc(sizeof(char) * (ns_list_str_len + 1)); // to be freed
    if (!ns_json || (ret = atcommons_enroll_namespace_list_to_json(ns_json, &ns_list_str_len, ep->ns_list)) != 0) {
      atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "Could not convert enroll_namespace_list to json. atcommons_enroll_namespace_list_to_json: %d\n", ret);
      cJSON_Delete(json); // Clean up the JSON object in case of an error
      ret = 1;
      goto exit;
    }
    ns_json[ns_list_str_len] = '\0'; // Null-terminate
    cJSON_AddRawToObject(json, NAMESPACES, ns_json);
  }

  // Add Base64-encoded strings directly to JSON
  if (ep->apkam_public_key) {
    cJSON_AddStringToObject(json, APKAM_PUBLIC_KEY, ep->apkam_public_key);
  }

  if (ep->encrypted_default_encryption_private_key) {
    cJSON_AddStringToObject(json, ENCRYPTED_DEFAULT_ENCRYPTION_PRIVATE_KEY, ep->encrypted_default_encryption_private_key);
  }

  if (ep->encrypted_self_encryption_key) {
    cJSON_AddStringToObject(json, ENCRYPTED_DEFAULT_SELF_ENCRYPTION_KEY, ep->encrypted_self_encryption_key);
  }

  if (ep->encrypted_apkam_symmetric_key) {
    cJSON_AddStringToObject(json, ENCRYPTED_APKAM_SYMMETRIC_KEY, ep->encrypted_apkam_symmetric_key);
  }

  // If only length is required
  if (json_string == NULL) {
    *json_string_len = strlen(cJSON_PrintUnformatted(json));
    ret = 1; // Return non-zero to indicate json_string was NULL
    goto exit;
  }

  // Populate json_string and calculate its length
  snprintf(*json_string, json_string_size, "%s", cJSON_PrintUnformatted(json));
  *json_string_len = strlen(*json_string);

exit:
  cJSON_Delete(json);
  if (ns_json) free(ns_json); // Properly free ns_json
  return ret;
}
