#include "atcommons/enroll_params.h"

#include <stddef.h>

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

int enroll_params_to_json(char **json_string, const enroll_params *ep) {
    int ret = 0;
    if (json_string == NULL) {
        ret = -1;
        return ret;
    }

    cJSON *json = cJSON_CreateObject();

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

    if (ep->ns_list->namespaces[0]) {
        char *ns_json;
        ret = enroll_namespace_list_to_json(&ns_json, ep->ns_list);
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
        cJSON_AddStringToObject(json,ENCRYPTED_DEFAULT_SELF_ENCRYPTION_KEY ,
                                (char *)ep->encrypted_default_self_encryption_key);
    }

    if (ep->encrypted_apkam_symmetric_key) {
        cJSON_AddStringToObject(json, ENCRYPTED_APKAM_SYMMETRIC_KEY,
                                (char *)ep->encrypted_apkam_symmetric_key);
    }

    *json_string = cJSON_PrintUnformatted(json);

exit:
    if (json) {
        cJSON_Delete(json);  // free the cJSON object
    }
    return ret;
}
