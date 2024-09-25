#include "atcommons/enroll_params.h"

#include <stddef.h>
#include <stdio.h>

#include "../../../../_deps/cjson-src/cJSON.h"

void init_enroll_params(EnrollParams *ep) {
    ep->enrollment_id = NULL;
    ep->app_name = NULL;
    ep->device_name = NULL;
    ep->otp = NULL;
    ep->ns_list = NULL;
    ep->apkam_public_key = NULL;
    ep->encrypted_default_encryption_private_key = NULL;
    ep->encrypted_default_self_encryption_key = NULL;
    ep->encrypted_apkam_symmetric_key = NULL;
}

int enroll_params_to_json(const char **json_string, const EnrollParams *ep) {
    int ret = 0;
    if (json_string == NULL) {
        ret = -1;
        return ret;
    }

    cJSON *json = cJSON_CreateObject();

    // Add each parameter to JSON only if it is not NULL
    if (ep->enrollment_id) {
        cJSON_AddStringToObject(json, "enrollmentId", ep->enrollment_id);
    }

    if (ep->app_name) {
        cJSON_AddStringToObject(json, "appName", ep->app_name);
    }

    if (ep->device_name) {
        cJSON_AddStringToObject(json, "deviceName", ep->device_name);
    }

    if (ep->otp) {
        cJSON_AddStringToObject(json, "otp", ep->otp);
    }

    puts(cJSON_Print(json));

    // Ensure at least one namespace is provided
    if (ep->ns_list->namespaces[0]) {
        char *ns_json;
        ret = enroll_namespace_list_to_json(&ns_json, ep->ns_list);
        cJSON_AddStringToObject(json, "namespaces", ns_json);
    }

    // Add Base64-encoded strings directly to JSON
    if (ep->apkam_public_key) {
        cJSON_AddStringToObject(json, "apkamPublicKey", (char *)ep->apkam_public_key);
    }

    if (ep->encrypted_default_encryption_private_key) {
        cJSON_AddStringToObject(json, "encryptedDefaultEncryptionPrivateKey",
                                (char *)ep->encrypted_default_encryption_private_key);
    }

    if (ep->encrypted_default_self_encryption_key) {
        cJSON_AddStringToObject(json, "encryptedDefaultSelfEncryptionKey",
                                (char *)ep->encrypted_default_self_encryption_key);
    }

    if (ep->encrypted_apkam_symmetric_key) {
        cJSON_AddStringToObject(json, "encryptedAPKAMSymmetricKey",
                                (char *)ep->encrypted_apkam_symmetric_key);
    }

    *json_string = cJSON_PrintUnformatted(json);

exit:
    if (json) {
        cJSON_Delete(json);  // Use cJSON_Delete to properly free the cJSON object
    }
    return ret;
}
