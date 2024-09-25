#include "atcommons/enroll_namespace_struct.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "../../../../_deps/cjson-src/cJSON.h"

int enroll_namespace_list_append(EnrollNamespaceList *ns_list, EnrollNamespace *ns) {
    int ret = 0;
    if (ns_list->length >= MAX_NAMESPACES) {
        ret = -1;
        return ret;
    }

    ns_list->namespaces[ns_list->length] = ns;
    ns_list->length++;

    return ret;
}

int enroll_namespace_to_json(char *ns_str, EnrollNamespace *ns) {
    int ret = 0;
    if (ns_str == NULL) {
        ret = -1;
        return ret;
    }

    snprintf(ns_str, "{\"%s\":\"%s\"}", ns->name, ns->access);

    return ret;
}

int enroll_namespace_list_to_json(char **ns_list_string, EnrollNamespaceList *ns_list) {
    int ret = 0;
    if (ns_list_string == NULL || *ns_list_string == NULL) {
        ret = -1;
        return ret;
    }

    cJSON *json_obj = cJSON_CreateObject();

    for (size_t ns_elmnt = 0; ns_elmnt < ns_list->length; ns_elmnt++) {
        cJSON_AddStringToObject(
            json_obj,
            ns_list->namespaces[ns_elmnt]->name,
            ns_list->namespaces[ns_elmnt]->access
        );
    }

    *ns_list_string = cJSON_PrintUnformatted(json_obj);

    if (json_obj) {
        cJSON_Delete(json_obj);
    }

    return ret;
}
