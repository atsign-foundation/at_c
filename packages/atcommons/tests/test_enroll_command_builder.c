#include "at_expect.c"
#include "atcommons/enroll_command_builder.h"
#include "atcommons/enroll_namespace.h"
#include "atcommons/enroll_params.h"
#include <stdlib.h>

#define TAG "test_enroll_command_builder"

int main() {
  int ret = 1;

  char expected_string[] = "enroll:request:{\"appName\":\"test-app\",\"deviceName\":\"test-device\",\"otp\":\"XYZABC\","
                           "\"namespaces\":{\"namespace1\":\"rw\",\"namespace2\":\"r\"}}";
  atcommons_enroll_namespace_t namespace;
  namespace.name = "namespace1";
  namespace.access = "rw";
  atcommons_enroll_namespace_t namespace2 = {"namespace2", "r"};

  atcommons_enroll_namespace_list_t *ns_list = malloc(sizeof(atcommons_enroll_namespace_list_t));
  atcommons_enroll_namespace_list_append(&ns_list, &namespace);
  atcommons_enroll_namespace_list_append(&ns_list, &namespace2);

  atcommons_enroll_params_t params;
  atcommons_enroll_params_init(&params);
  params.app_name = "test-app";
  params.device_name = "test-device";
  params.otp = "XYZABC";
  params.ns_list = ns_list;

  size_t cmd_size = 0;
  atcommons_build_enroll_command(NULL, 0, &cmd_size, atcommons_apkam_request, &params);
  char *command = malloc(sizeof(char) * cmd_size);
  size_t cmd_len = 0;
  ret = atcommons_build_enroll_command(command, sizeof(char) * cmd_size, &cmd_len, atcommons_apkam_request, &params);
  if (ret != 0) {
    goto exit;
  }

  ret = atcommons_string_expect(command, expected_string);

exit: {
  free(command);
  return ret;
}
}