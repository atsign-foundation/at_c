#include "atcommons/enroll_command_builder.h"
#include "atcommons/enroll_namespace.h"
#include "atcommons/enroll_params.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
int main() {
  int ret = 1;

  char expected_string[] = "enroll:request:{\"appName\":\"test-app\",\"deviceName\":\"test-device\",\"otp\":\"XYZABC\","
                           "\"namespaces\":{\"namespace1\":\"rw\",\"namespace2\":\"r\"}}";
  enroll_namespace_t namespace;
  namespace.name = "namespace1";
  namespace.access = "rw";
  enroll_namespace_t namespace2 = {"namespace2", "r"};

  enroll_namespace_list_t *ns_list = malloc(sizeof(enroll_namespace_list_t));
  atcommons_enroll_namespace_list_append(&ns_list, &namespace);
  atcommons_enroll_namespace_list_append(&ns_list, &namespace2);

  enroll_params_t params;
  atcommons_enroll_params_init(&params);
  params.app_name = "test-app";
  params.device_name = "test-device";
  params.otp = "XYZABC";
  params.ns_list = ns_list;

  char *command = malloc(sizeof(char) * ENROLL_COMMAND_MAX_LENGTH);
  size_t cmd_len = 0;
  ret = atcommons_build_enroll_command(command, sizeof(char) * ENROLL_COMMAND_MAX_LENGTH, &cmd_len, apkam_request,
                                       &params);
  if (ret != 0) {
    goto exit;
  }
  printf("%s\n", command);
  printf("%s\n", expected_string);

  ret = strncmp(command, expected_string, strlen(expected_string));
  if (ret == 0) {
    printf("test passed\n");
  } else {
    printf("test failed | ret: %d\n", ret);
  }

exit: {
  fflush(stdout);
  free(command);
  return ret;
}
}