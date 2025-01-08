#include <atclient/atclient.h>
#include <atclient/atkeys.h>
#include <atclient/atkeys_file.h>
#include <atlogger/atlogger.h>
#include <string.h>
#include <functional_tests/config.h>
#include <functional_tests/helpers.h>

#define TAG "test_atkeys_write"

#define ATKEYS_FILE_PATH_COPY "temp_key.atKeys"

int main(int argc, char *argv[]) {
  int ret = 1;

  atlogger_set_logging_level(ATLOGGER_LOGGING_LEVEL_DEBUG);

  atclient_atkeys atkeys;
  atclient_atkeys_init(&atkeys);

  atclient_atkeys atkeys1;
  atclient_atkeys_init(&atkeys1);

  atclient atclient1;
  atclient_init(&atclient1);

  atclient_authenticate_options authenticate_options;
  atclient_authenticate_options_init(&authenticate_options);

  if ((ret = functional_tests_set_up_atkeys(&atkeys, FIRST_ATSIGN)) != 0) { // populate `atkeys` from `~/.atsign/keys/@atsign_key.atKeys`
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "failed to populate atkeys from string\n");
    goto exit;
  }

  // log what fields are initializwed
  atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_DEBUG, "is_pkam_public_key_base64_initialized: %d\n",
               atclient_atkeys_is_pkam_public_key_base64_initialized(&atkeys));
  atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_DEBUG, "is_pkam_private_key_base64_initialized: %d\n",
               atclient_atkeys_is_pkam_private_key_base64_initialized(&atkeys));
  atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_DEBUG, "is_encrypt_public_key_base64_initialized: %d\n",
               atclient_atkeys_is_encrypt_public_key_base64_initialized(&atkeys));
  atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_DEBUG, "is_encrypt_private_key_base64_initialized: %d\n",
               atclient_atkeys_is_encrypt_private_key_base64_initialized(&atkeys));
  atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_DEBUG, "is_self_encryption_key_base64_initialized: %d\n",
               atclient_atkeys_is_self_encryption_key_base64_initialized(&atkeys));
  atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_DEBUG, "is_apkam_symmetric_key_base64_initialized: %d\n",
               atclient_atkeys_is_apkam_symmetric_key_base64_initialized(&atkeys));
  atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_DEBUG, "is_enrollment_id_initialized: %d\n",
               atclient_atkeys_is_enrollment_id_initialized(&atkeys));

  if ((ret = atclient_atkeys_write_to_path(&atkeys, ATKEYS_FILE_PATH_COPY))) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "failed to write to path\n");
    goto exit;
  }

  if ((ret = atclient_atkeys_populate_from_path(&atkeys1, ATKEYS_FILE_PATH_COPY))) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "failed to populate from path\n");
    goto exit;
  }

  // log what fields are initializwed
  atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_DEBUG, "is_pkam_public_key_base64_initialized: %d\n",
               atclient_atkeys_is_pkam_public_key_base64_initialized(&atkeys1));
  atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_DEBUG, "is_pkam_private_key_base64_initialized: %d\n",
               atclient_atkeys_is_pkam_private_key_base64_initialized(&atkeys1));
  atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_DEBUG, "is_encrypt_public_key_base64_initialized: %d\n",
               atclient_atkeys_is_encrypt_public_key_base64_initialized(&atkeys1));
  atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_DEBUG, "is_encrypt_private_key_base64_initialized: %d\n",
               atclient_atkeys_is_encrypt_private_key_base64_initialized(&atkeys1));
  atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_DEBUG, "is_self_encryption_key_base64_initialized: %d\n",
               atclient_atkeys_is_self_encryption_key_base64_initialized(&atkeys1));
  atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_DEBUG, "is_apkam_symmetric_key_base64_initialized: %d\n",
               atclient_atkeys_is_apkam_symmetric_key_base64_initialized(&atkeys1));
  atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_DEBUG, "is_enrollment_id_initialized: %d\n",
               atclient_atkeys_is_enrollment_id_initialized(&atkeys1));

  // compare the two atkeys
  if (strcmp(atkeys.pkam_public_key_base64, atkeys1.pkam_public_key_base64) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "pkam_public_key_base64 mismatch\n");
    goto exit;
  }

  if (strcmp(atkeys.pkam_private_key_base64, atkeys1.pkam_private_key_base64) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "pkam_private_key_base64 mismatch\n");
    goto exit;
  }

  if (strcmp(atkeys.encrypt_public_key_base64, atkeys1.encrypt_public_key_base64) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "encrypt_public_key_base64 mismatch\n");
    goto exit;
  }

  if (strcmp(atkeys.encrypt_private_key_base64, atkeys1.encrypt_private_key_base64) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "encrypt_private_key_base64 mismatch\n");
    goto exit;
  }

  if (strcmp(atkeys.self_encryption_key_base64, atkeys1.self_encryption_key_base64) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "self_encryption_key_base64 mismatch\n");
    goto exit;
  }

  if ((ret = atclient_authenticate_options_set_atdirectory_host(&authenticate_options, ATDIRECTORY_HOST)) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "failed to set atdirectory host\n");
    goto exit;
  }

  if ((ret = atclient_authenticate_options_set_atdirectory_port(&authenticate_options, ATDIRECTORY_PORT)) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "failed to set atdirectory port\n");
    goto exit;
  }

  if ((ret = atclient_pkam_authenticate(&atclient1, FIRST_ATSIGN, &atkeys1, &authenticate_options, NULL)) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "failed to pkam auth\n");
    goto exit;
  }

exit: {
  atclient_atkeys_free(&atkeys);
  atclient_atkeys_free(&atkeys1);
  atclient_free(&atclient1);
  return ret;
}
}
