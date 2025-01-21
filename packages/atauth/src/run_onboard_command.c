#include "run_onboard_command.h"
#include "apkam_keys.h"
#include "atclient/atclient.h"
#include "atclient/atclient_utils.h"
#include "atclient/atkey.h"
#include "atclient/atkeys.h"
#include "atclient/atkeys_file.h"
#include "atclient/request_options.h"
#include "atlogger/atlogger.h"
#include "constants.h"
#include "enroll_operation.h"
#include "enroll_params.h"
#include "enroll_request.h"
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define TAG "atauth_onboard_command"

int atauth_onboard_command(const char *atsign, const char *root_domain, const char *keys_path, const char *cram_key) {
  int ret = 0;

  // Resolve atkeys file & ensure file doesn't already exist
  const char *resolved_atkeys_path;
  char *atkeys_path = NULL; // free me if I'm not null
  if (keys_path == NULL) {
    atkeys_path = atkeys_file_get_default_path(atsign);
    if (atkeys_path == NULL) {
      atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "Failed to get default atKeys file path\n");
      return 1;
    }
    if (atkeys_path != NULL && access(atkeys_path, F_OK) == 0) {
      atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atKeys file already exists at: %s\n", atkeys_path);
      free(atkeys_path);
      return 1;
    }
    resolved_atkeys_path = atkeys_path;
  } else {
    if (keys_path != NULL && access(keys_path, F_OK) == 0) {
      atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atKeys file already exists at: %s\n", keys_path);
      return 1;
    }
    resolved_atkeys_path = keys_path;
  }

  // connect to atServer via cram auth
  atclient atclient;
  atclient_init(&atclient); // free me

  atclient_authenticate_options auth_opts;
  atclient_authenticate_options_init(&auth_opts); // free me

  ret =
      atclient_utils_find_atserver_address(root_domain, 64, atsign, &auth_opts.atserver_host, &auth_opts.atserver_port);
  if (ret != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "Failed to lookup the atserver host & port\n");
    goto free_auth_options;
  }

  ret = atclient_cram_authenticate(&atclient, atsign, cram_key, &auth_opts);
  if (ret != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "Failed to cram authenticate to the atserver\n");
    goto free_auth_options;
  }

  // generate new apkam keys
  struct atauth_apkam_keys apkam_keys;
  atauth_apkam_keys_init(&apkam_keys); // free me

  ret = atauth_apkam_keys_generate_all(&apkam_keys);
  if (ret != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "Failed to generate apkam keys\n");
    goto free_apkam_keys;
  }

  // send enroll request
  atauth_enroll_params_t ep = {
      .app_name = ATAUTH_DEFAULT_FIRST_APP_NAME,
      .device_name = ATAUTH_DEFAULT_FIRST_DEVICE_NAME,
      .apkam_public_key = apkam_keys.pkam_public_key_base64,
      .encrypted_default_encryption_private_key = apkam_keys.encrypted_encrypt_private_key_base64,
      .encrypted_default_encryption_private_key_iv = apkam_keys.encrypted_encrypt_private_iv_base64,
      .encrypted_self_encryption_key = apkam_keys.encrypted_self_encryption_key_base64,
      .encrypted_self_encryption_key_iv = apkam_keys.encrypted_self_encryption_key_iv_base64,
  };

  struct enroll_response response;
  ret = atauth_send_enroll_request(&atclient, &ep, atauth_apkam_request, &response);
  if (ret != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atauth_send_enroll_request: %d\n", ret);
    goto free_apkam_keys;
  }

  // convert apkam_keys into an atkeys
  atclient_atkeys *atkeys;
  ret = atauth_apkam_keys_create_atkeys(&apkam_keys, &atkeys);
  if (ret != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "Failed to create the atkeys from the generated apkam keys\n");
    goto free_enroll_response;
  }

  ret = atclient_atkeys_set_enrollment_id(atkeys, response.enrollment_id, strlen(response.enrollment_id));
  if (ret != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "Failed to set enrollment_id in atkeys\n");
    goto free_atkeys;
  }

  // disconnect
  atclient_connection_disconnect(&atclient.atserver_connection);
  atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_DEBUG, "Terminated cram instance of atserver connection\n");

  // pkam auth
  ret = atclient_pkam_authenticate(&atclient, atsign, atkeys, &auth_opts, NULL);
  if (ret != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "Failed to pkam auth to the atServer\n");
    goto free_atkeys;
  }

  // write atKeys to atKeys file
  ret = atclient_atkeys_write_to_path(atkeys, resolved_atkeys_path);
  if (ret != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "Failed to write the atkeys file\n");
    goto free_atkeys;
  }

  // upload default enc public key to atServer
  atclient_atkey encrypt_public_atkey;
  atclient_atkey_init(&encrypt_public_atkey);

  ret = atclient_atkey_create_public_key(&encrypt_public_atkey, "publickey", atsign, NULL);
  if (ret != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "Failed to create atkey for encrypt public key\n");
    goto free_encrypt_public_atkey;
  }

  ret = atclient_atkey_metadata_set_is_public(&encrypt_public_atkey.metadata, true);
  if (ret != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "Failed to set is_public=true on atkey for encrypt public key\n");
    goto free_encrypt_public_atkey;
  }

  ret = atclient_put_public_key(&atclient, &encrypt_public_atkey, atkeys->encrypt_public_key_base64, NULL, NULL);
  if (ret != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "Failed to put encrypt public key to atServer\n");
    goto free_encrypt_public_atkey;
  }

  // delete cram secret from atServer
  atclient_atkey cram_atkey;
  atclient_atkey_init(&cram_atkey);

  ret = atclient_atkey_create_reserved_key(&cram_atkey, "privatekey:at_secret");
  if (ret != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "Failed to create atkey for cram secret\n");
    goto free_cram_atkey;
  }

  atclient_delete_request_options delete_req_opts;
  atclient_delete_request_options_init(&delete_req_opts);
  atclient_delete_request_options_set_skip_shared_by_check(&delete_req_opts, true);
  ret = atclient_delete(&atclient, &cram_atkey, &delete_req_opts, NULL);
  atclient_delete_request_options_free(&delete_req_opts);
  if (ret != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "Failed to delete cram secret from atServer\n");
    goto free_cram_atkey;
  }

  // done
free_cram_atkey:
  atclient_atkey_free(&cram_atkey);
free_encrypt_public_atkey:
  atclient_atkey_free(&encrypt_public_atkey);
free_atkeys:
  atclient_connection_disconnect(&atclient.atserver_connection);
  atclient_atkeys_free(atkeys);
free_enroll_response:
  free_enroll_response(&response);
free_apkam_keys:
  atauth_apkam_keys_free(&apkam_keys);
free_auth_options:
  atclient_free(&atclient);
  atclient_authenticate_options_free(&auth_opts);
  if (atkeys_path != NULL) {
    free(atkeys_path);
  }
  return ret;
}
