#include "atlogger/atlogger.h"
#include "enroll_namespace.h"
#include "enroll_request.h"
#include <string.h>

#define TAG "test_enroll_request"

static int test_1a_generate_onboard_command_valid();

int main() {
  int ret = 0;
  atlogger_set_logging_level(ATLOGGER_LOGGING_LEVEL_INFO);

  ret += test_1a_generate_onboard_command_valid();

  if (ret != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "%d tests failed\n", ret);
  }

  return ret;
}

#define t1a_appname "foo"
#define t1a_devname "bar"
#define t1a_apkam_pubkey "APKAMPUBKEY"
#define t1a_def_privkey "DEFPRIVKEY"
#define t1a_def_iv "DEFIV"
#define t1a_self_key "SELFKEY"
#define t1a_self_iv "SELFIV"
static int test_1a_generate_onboard_command_valid() {
  enum namespace_permissions perms[2] = {np_readonly, np_read_write};
  char *ns_list[2] = {"buzz", "wavi"};
  struct enroll_namespace namespaces = {
      .len = 2,
      .namespaces = ns_list,
      .permissions = perms,
  };
  atauth_enroll_params_t ep = {
      .app_name = t1a_appname,
      .device_name = t1a_devname,
      .apkam_public_key = t1a_apkam_pubkey,
      .encrypted_default_encryption_private_key = t1a_def_privkey,
      .encrypted_default_encryption_private_key_iv = t1a_def_iv,
      .encrypted_self_encryption_key = t1a_self_key,
      .encrypted_self_encryption_key_iv = t1a_self_iv,
      .namespaces = &namespaces,
  };

  char *command;
  int ret = atauth_generate_enroll_command_string(&ep, atauth_apkam_request, &command);
  if (ret != 0) {
    atlogger_log(TAG " 1a", ATLOGGER_LOGGING_LEVEL_ERROR, "Failed to generate enroll command string\n");
    return 1;
  }

  char *expected_string = "enroll:request:{"
                          "\"appName\":\"" t1a_appname "\","
                          "\"deviceName\":\"" t1a_devname "\","
                          "\"namespaces\":{\"buzz\":\"r\",\"wavi\":\"rw\"},"
                          "\"apkamPublicKey\":\"" t1a_apkam_pubkey "\","
                          "\"encryptedDefaultEncryptionPrivateKey\":\"" t1a_def_privkey "\","
                          // TODO IV "\"encryptedDefaultEncryptionPrivateKey\":\"" t1a_def_privkey "\","
                          "\"encryptedDefaultSelfEncryptionKey\":\"" t1a_self_key "\"" // TODO adjust commas later
                          // TODO IV "\"encryptedDefaultSelfEncryptionKey\":\"" t1a_self_key "\","
                          "}\n";
  size_t expected_len = strlen(expected_string);
  size_t command_len = strlen(command);
  if (expected_len != command_len) {
    atlogger_log(TAG " 1a", ATLOGGER_LOGGING_LEVEL_ERROR,
                 "Command string length did not match expected string length: expected %zu, actual %zu\n\t\texpected "
                 "string: '%s',\n\t\tactual string:   '%s'",
                 expected_len, command_len, expected_string, command);

    ret = 1;
    goto exit;
  }

  ret = strcmp(expected_string, command);
  if (ret != 0) {
    atlogger_log(TAG " 1a", ATLOGGER_LOGGING_LEVEL_ERROR,
                 "Command string did not match expected string: expected '%s', actual '%s'\n", expected_string,
                 command);
    ret = 1;
    goto exit;
  }

  ret = 0;
exit:
  free(command);
  return ret;
}
