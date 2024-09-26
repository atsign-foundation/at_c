#include <atcommons/enroll_namespace.h>
#include <atcommons/enroll_operation.h>
#include <atcommons/enroll_params.h>
#include <atcommons/enroll_command_builder.h>

#include <stdio.h>
#include <stdlib.h>

int main() {
    // create an enroll_namespace
    EnrollNamespace namespace;
    namespace.name = "namespace1";
    namespace.access = "rw";

    // another way to create an enroll namespace
    EnrollNamespace namespace2 = {"namespace2", "r"};

    EnrollNamespaceList *ns_list = malloc(sizeof(EnrollNamespaceList));
    enroll_namespace_list_append(ns_list, &namespace);
    enroll_namespace_list_append(ns_list, &namespace2);

    EnrollParams *params;
    params->app_name = "test-app";
    params->device_name = "test-device";
    params->otp = "XYZABC";
    params->ns_list = ns_list;

    char *command = malloc(sizeof(char) * 1500);

    int ret = 0;
    ret = enroll_verb_build_command(command, request, params);

    printf("command: %s", command);

    return 0;
}
