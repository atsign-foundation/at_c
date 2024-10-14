#include "atclient/atclient.h"
#include "atlogger/atlogger.h"
#include "atcommons/enroll_namespace.h"
#include "atcommons/enroll_params.h"
#include "atauth/send_enroll_request.h"
#include "atchops/base64.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main() {
    atclient client;
    if (atclient_init(&client) != 0) {
        atlogger_log("TEST", ATLOGGER_LOGGING_LEVEL_ERROR, "Failed to initialize client");
        return -1;
    }

    enroll_namespace_t namespace1 = {"kingslanding", "rw"};
    enroll_namespace_t namespace2 = {"winterfell", "r"};

    // Allocate memory for ns_list with initial size for 2 namespaces
    enroll_namespace_list_t *ns_list = malloc(sizeof(enroll_namespace_list_t) + sizeof(enroll_namespace_t *) * 2);
    if (!ns_list) {
        atlogger_log("TEST", ATLOGGER_LOGGING_LEVEL_ERROR, "Failed to allocate memory for namespace list");
        return -1;
    }
    memset(ns_list, 0, sizeof(enroll_namespace_list_t));
    ns_list->length = 0;

    // Append namespaces to ns_list
    int ret = atcommons_enroll_namespace_list_append(&ns_list, &namespace1);

    ret = atcommons_enroll_namespace_list_append(&ns_list, &namespace2);

    ret = atcommons_enroll_namespace_list_append(&ns_list, &(enroll_namespace_t){"riverlands", "rw"});

    // Allocate and initialize enroll_params_t
    enroll_params_t *params = malloc(sizeof(enroll_params_t));
    if (!params) {
        atlogger_log("TEST", ATLOGGER_LOGGING_LEVEL_ERROR, "Failed to allocate memory for enroll_params_t");
        free(ns_list);
        return -1;
    }
    enroll_params_init(params);

    // Assign parameters
    params->app_name = "test-app";
    params->device_name = "test-device";
    params->otp = "XYZABC";
    params->ns_list = ns_list;
    params->apkam_keys_expiry_in_millis = 6969;

    atlogger_log("TEST", ATLOGGER_LOGGING_LEVEL_INFO, "Initialization success");

    // Allocate memory for enroll_id and send the enroll request
    char enroll_id[ENROLL_ID_MAX_LEN];
    char enroll_status[10];

    ret = atauth_send_enroll_request(&enroll_id, &enroll_status, &client, params);
    printf("Final ret: %d\n", ret);
    if (ret == 0) {
        printf("Enroll ID: %s\n", enroll_id);
    } else {
        atlogger_log("TEST", ATLOGGER_LOGGING_LEVEL_ERROR, "Enroll request failed");
    }

    // Clean up
    free(ns_list);
    free(params);

    return ret;
}
