#include "run_enroll_command.h"
#include "resolve_atserver.h"
#include "apkam_keys.h"
#include "atchops/aes_ctr.h"
#include "atchops/base64.h"
#include "atchops/iv.h"
#include "atclient/atclient.h"
#include "atclient/atclient_utils.h"
#include "atclient/atkeys.h"
#include "atclient/atkeys_file.h"
#include "atclient/constants.h"
#include "atclient/string_utils.h"
#include "atlogger/atlogger.h"
#include "constants.h"
#include "enroll_namespace.h"
#include "enroll_params.h"
#include "enroll_request.h"
#include "enroll_response.h"
#include "wait_for_enrollment.h"
#include <atclient/json.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define TAG "ENROLL"

static int fetch_and_decrypt_key(atclient_connection *conn, const char *key_name, const char *enrollment_id,
                                 const char *atsign, const unsigned char *, char **key);
int atauth_enroll_command(const char *atsign, const char *root_domain, const char *keys_path, const char *passcode,
                          const char *app, const char *device, const char *namespaces, const char *expiry) {
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

  ret = atauth_resolve_atserver(root_domain, atsign, &auth_opts.atserver_host, &auth_opts.atserver_port);
  if (ret != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "Failed to lookup the atserver host & port\n");
    goto free_auth_options;
  }

  ret = atclient_start_atserver_connection(&atclient, auth_opts.atserver_host, auth_opts.atserver_port);
  if (ret != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "Failed to connect to the atServer\n");
    goto free_auth_options;
  }

  if (strncmp(root_domain, "proxy:", strlen("proxy:")) == 0) {
    // A protocol-aware reverse proxy (e.g. proxy0001.atsign.org:443) routes a
    // connection using the FIRST line the client sends, and only understands
    // 'from:' - any other first line makes it answer with its own address and
    // close the socket. The enroll flow's first real command is a lookup, so
    // in proxy mode issue a from: exchange first and discard the challenge;
    // the connection is then bridged to the atServer and every subsequent
    // command flows through. (The atServer still accepts unauthenticated
    // lookup/enroll verbs after a bare from:.)
    char *atsign_without_at = NULL;
    ret = atclient_string_utils_atsign_without_at(atsign, &atsign_without_at);
    if (ret != 0) {
      atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "Failed to strip the '@' from the atsign\n");
      goto free_auth_options;
    }
    const size_t from_cmd_size = strlen("from:") + strlen(atsign_without_at) + strlen("\r\n") + 1;
    char *from_cmd = malloc(from_cmd_size);
    if (from_cmd == NULL) {
      atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "Failed to allocate memory for from_cmd\n");
      free(atsign_without_at);
      ret = 1;
      goto free_auth_options;
    }
    snprintf(from_cmd, from_cmd_size, "from:%s\r\n", atsign_without_at);
    free(atsign_without_at);
    const size_t from_recv_size = 256;
    unsigned char from_recv[from_recv_size];
    size_t from_recv_len = 0;
    ret = atclient_connection_send(&atclient.atserver_connection, (unsigned char *)from_cmd, strlen(from_cmd),
                                   from_recv, sizeof(unsigned char) * from_recv_size, &from_recv_len);
    free(from_cmd);
    if (ret != 0) {
      atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "Failed to route the connection via the reverse proxy\n");
      goto free_auth_options;
    }
  }

  atclient_atkeys atkeys;
  atclient_atkeys_init(&atkeys);

  atclient_atkey enc_pub_key;
  atclient_atkey_init(&enc_pub_key);

  ret = atclient_atkey_create_public_key(&enc_pub_key, "publickey", atsign, NULL);
  if (ret != 0) {
    goto free_enc_pub_key;
  }

  char *default_encryption_public_key;
  atclient_get_public_key_request_options pubkey_opts;
  atclient_get_public_key_request_options_init(&pubkey_opts);

  ret = atclient_get_public_key(&atclient, &enc_pub_key, &default_encryption_public_key, &pubkey_opts);
  atclient_get_public_key_request_options_free(&pubkey_opts);
  if (ret != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "Failed to get the default encryption public key\n");
    goto free_enc_pub_key;
  }

  size_t default_encryption_public_key_len = strlen(default_encryption_public_key);
  ret = atclient_atkeys_set_encrypt_public_key_base64(&atkeys, default_encryption_public_key,
                                                      default_encryption_public_key_len);
  if (ret != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "Failed to load encrypt public key into atkeys\n");
    goto free_default_encryption_public_key;
  }
  ret = atclient_atkeys_populate_encrypt_public_key(&atkeys, default_encryption_public_key,
                                                    default_encryption_public_key_len);
  if (ret != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "Failed to populate encrypt public key into atkeys\n");
    goto free_default_encryption_public_key;
  }

  // generate new apkam keys
  struct atauth_generated_apkam_enrollment_keys apkam_keys;
  atauth_generated_apkam_enrollment_keys_init(&apkam_keys);

  ret = atauth_generated_apkam_enrollment_keys_generate(&apkam_keys, &atkeys.encrypt_public_key);
  if (ret != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "Failed to generate apkam keys\n");
    goto free_apkam_keys;
  }

  ret = atauth_generated_apkam_enrollment_keys_populate_atkeys(&apkam_keys, &atkeys);
  if (ret != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "Failed to populate generated keys into atkeys\n");
    goto free_apkam_keys;
  }

  struct enroll_namespace ns;
  ret = parse_enroll_namespace(namespaces, &ns);
  if (ret != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "Failed to parse namespace list\n");
    goto free_apkam_keys;
  }

  int64_t exp_ms = 0;
  if (expiry != NULL) {
    exp_ms = atoll(expiry);
    if (exp_ms <= 0) {
      atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "Invalid --expiry value: %s (expected a positive number of ms)\n",
                   expiry);
      ret = 1;
      goto free_namespace_list;
    }
  }
  // send enroll request
  atauth_enroll_params_t ep = {
      .app_name = (char *)app,
      .device_name = (char *)device,
      .otp = (char *)passcode,
      .namespaces = &ns,
      .apkam_keys_expiry_in_millis = exp_ms,
      .apkam_public_key = apkam_keys.apkam_public_key,
      .encrypted_apkam_symmetric_key = apkam_keys.apkam_symmetric_key.encrypted_symmetric_key_base64,
  };

  struct enroll_response response;
  ret = atauth_send_enroll_request(&atclient, &ep, atauth_apkam_request, &response);
  if (ret != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atauth_send_enroll_request: %d\n", ret);
    goto free_namespace_list;
  }

  ret = atclient_atkeys_set_enrollment_id(&atkeys, response.enrollment_id, strlen(response.enrollment_id));
  if (ret != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "Failed to set enrollment_id in atkeys\n");
    goto free_enroll_response;
  }

  // disconnect
  atclient_connection_disconnect(&atclient.atserver_connection);
  atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_DEBUG, "Terminated cram instance of atserver connection\n");

  // pkam auth
  ret = wait_for_enrollment(&atclient, atsign, &atkeys, &auth_opts);
  if (ret != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "Enrollment was rejected\n");
    goto free_enroll_response;
  }

  // fetch default encryption private key from server
  char *encrypt_private_key;
  ret = fetch_and_decrypt_key(&atclient.atserver_connection, ATAUTH_ENCRYPTED_DEFAULT_ENC_PRIVKEY_NAME,
                              response.enrollment_id, atsign, apkam_keys.apkam_symmetric_key.symmetric_key_raw,
                              &encrypt_private_key);
  if (ret != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "Failed to fetch and decrypt %s key\n",
                 ATAUTH_ENCRYPTED_DEFAULT_ENC_PRIVKEY_NAME);
    goto free_enroll_response;
  }

  // populate atkeys with default encryption key

  size_t encrypt_private_key_len = strlen(encrypt_private_key);
  ret = atclient_atkeys_set_encrypt_private_key_base64(&atkeys, encrypt_private_key, encrypt_private_key_len);
  if (ret != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "Failed to load encrypt private key in atkeys\n");
    goto free_priv_key;
  }
  ret = atclient_atkeys_populate_encrypt_private_key(&atkeys, encrypt_private_key, encrypt_private_key_len);
  if (ret != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "Failed to populate encrypt private key in atkeys\n");
    goto free_priv_key;
  }

  // fetch self encryption key from server
  char *self_encryption_key;
  ret = fetch_and_decrypt_key(&atclient.atserver_connection, ATAUTH_ENCRYPTED_SELF_ENC_KEY_NAME, response.enrollment_id,
                              atsign, apkam_keys.apkam_symmetric_key.symmetric_key_raw, &self_encryption_key);

  if (ret != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "Failed to fetch and decrypt %s key\n",
                 ATAUTH_ENCRYPTED_SELF_ENC_KEY_NAME);
    goto free_priv_key;
  }
  // populate atkeys with self encryption key
  ret = atclient_atkeys_set_self_encryption_key_base64(&atkeys, self_encryption_key, strlen(self_encryption_key));
  if (ret != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "Failed to load self encryption key in atkeys\n");
    goto free_self_enc_key;
  }

  // write atKeys to atKeys file
  ret = atclient_atkeys_write_to_path(&atkeys, resolved_atkeys_path);
  if (ret != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "Failed to write the atkeys file\n");
    goto free_self_enc_key;
  }

  atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_INFO, "Enrollment complete, keys have been written to %s\n",
               resolved_atkeys_path);
free_self_enc_key:
  free(self_encryption_key);
free_priv_key:
  free(encrypt_private_key);
free_enroll_response:
  free_enroll_response(&response);
free_namespace_list:
  enroll_namespace_free(&ns);
free_apkam_keys:
  atauth_generated_apkam_enrollment_keys_free(&apkam_keys);
free_default_encryption_public_key:
  free(default_encryption_public_key);
free_enc_pub_key:
  atclient_atkey_free(&enc_pub_key);
  atclient_atkeys_free(&atkeys);
free_auth_options:
  atclient_connection_disconnect(&atclient.atserver_connection);
  atclient_free(&atclient);
  atclient_authenticate_options_free(&auth_opts);
  if (atkeys_path != NULL) {
    free(atkeys_path);
  }
  return ret;
}

static int fetch_and_decrypt_key(atclient_connection *conn, const char *key_name, const char *enrollment_id,
                                 const char *atsign, const unsigned char *apkam_symmetric_key, char **key) {
  int ret;

  const size_t cmd_size =
      strlen("keys:get:keyName:..__manage\r\n") + strlen(enrollment_id) + strlen(key_name) + strlen(atsign) + 1;
  char cmd[cmd_size];
  snprintf(cmd, cmd_size, "keys:get:keyName:%s.%s.__manage%s\r\n", enrollment_id, key_name, atsign);

  const size_t recv_size = 2400;
  unsigned char recv[recv_size];
  memset(recv, 0, sizeof(char) * recv_size);
  size_t recv_len = 0;
  // recv_size - 1 keeps the memset-provided NUL intact even if the server
  // reply fills the buffer exactly
  ret = atclient_connection_send(conn, (unsigned char *)cmd, strlen(cmd), recv, recv_size - 1, &recv_len);
  if (ret != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "Failed to send keys:get verb for %s: %d\n", key_name, ret);
    return ret;
  }

  // An error reply must not be mis-parsed as success just because it happens
  // to contain "data:" somewhere in its message
  char *error_pos = NULL;
  char *response_trimmed = NULL;
  const bool has_error = atclient_string_utils_get_substring_position((char *)recv, "error:", &error_pos) == 0;
  const bool has_data = atclient_string_utils_get_substring_position((char *)recv, ATCLIENT_DATA_TOKEN, &response_trimmed) == 0;
  if (!has_data || (has_error && error_pos < response_trimmed)) {
    ret = 1;
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "recv was \"%.*s\" and did not have prefix \"data:\"\n",
                 (int)recv_len, recv);
    return ret;
  }
  response_trimmed = response_trimmed + strlen(ATCLIENT_DATA_TOKEN);

  // Parse response json
  cJSON *json_server_resp = cJSON_Parse(response_trimmed);
  if (json_server_resp == NULL) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "Error parsing server response JSON\n");
    ret = 1;
    return ret;
  }
  unsigned char iv_raw[ATCHOPS_IV_BUFFER_SIZE] = {0};

  const cJSON *key_json = cJSON_GetObjectItemCaseSensitive(json_server_resp, "value");
  if (!cJSON_IsString(key_json)) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "Error: Missing \"value\" in server response JSON\n");
    ret = 1;
    cJSON_Delete(json_server_resp);
    return ret;
  }

  char *key_encrypted_base64 = cJSON_GetStringValue(key_json);
  size_t key_encrypted_base64_len = strlen(key_encrypted_base64);
  size_t key_encrypted_len = atchops_base64_decoded_size(key_encrypted_base64_len);
  unsigned char key_encrypted[key_encrypted_len];
  ret = atchops_base64_decode(key_encrypted_base64, key_encrypted_base64_len, key_encrypted, key_encrypted_len,
                              &key_encrypted_len);
  if (ret != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "Failed to base64 decode encrypted key\n");
    cJSON_Delete(json_server_resp);
    return ret;
  }

  // use 0 iv if no iv was shared with us (legacy behavior)
  if (cJSON_HasObjectItem(json_server_resp, "iv")) {
    const cJSON *iv_json = cJSON_GetObjectItemCaseSensitive(json_server_resp, "iv");
    if (!cJSON_IsString(iv_json)) {
      atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "Error: \"iv\" in server response JSON is not a string\n");
      cJSON_Delete(json_server_resp);
      return 1;
    }
    char *iv_base64 = cJSON_GetStringValue(iv_json);
    size_t iv_base64_len = strlen(iv_base64);
    size_t iv_raw_len;
    ret = atchops_base64_decode(iv_base64, iv_base64_len, iv_raw, ATCHOPS_IV_BUFFER_SIZE, &iv_raw_len);
    if (ret != 0) {
      atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "Failed to base64 decode iv\n");
      cJSON_Delete(json_server_resp);
      return ret;
    }
    if (iv_raw_len != ATCHOPS_IV_BUFFER_SIZE) {
      atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR,
                   "Unexpected size for base64 decoded iv (expected: %zu, actual: %zu)\n",
                   (size_t)ATCHOPS_IV_BUFFER_SIZE, iv_raw_len);
      cJSON_Delete(json_server_resp);
      return 1;
    }
  }

  size_t decrypted_key_len = atchops_aes_ctr_plaintext_size(key_encrypted_len);
  unsigned char decrypted_key[decrypted_key_len + 1];
  ret = atchops_aes_ctr_decrypt(apkam_symmetric_key, ATCHOPS_AES_256, iv_raw, key_encrypted, key_encrypted_len,
                                decrypted_key, decrypted_key_len, &decrypted_key_len);
  if (ret != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "Failed to decrypt key: %d\n", ret);
    cJSON_Delete(json_server_resp);
    return ret;
  }
  decrypted_key[decrypted_key_len] = 0;
  *key = malloc(sizeof(char) * (decrypted_key_len + 1));
  if (*key == NULL) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "Failed to allocate memory for key out\n");
    cJSON_Delete(json_server_resp);
    return 1;
  }
  memcpy(*key, decrypted_key, decrypted_key_len);
  (*key)[decrypted_key_len] = 0;

  cJSON_Delete(json_server_resp);
  return 0;
}
