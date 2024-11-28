#include <atauth/atactivate_arg_parser.h>
#include <atauth/atauth_build_atkeys_file_path.h>
#include <atauth/send_enroll_request.h>
#include <atchops/aes.h>
#include <atchops/aes_ctr.h>
#include <atchops/base64.h>
#include <atchops/iv.h>
#include <atchops/utf8.h>
#include <atcommons/enroll_status.h>
#include <atlogger/atlogger.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define TAG "Auth CLI"
#define AES_256_KEY_BYTES 32
#define DEFAULT_APKAM_RETRY_INTERVAL 10 // seconds
#define MAX_APKAM_AUTH_RETRY_ATTMEPTS 10
#define ENROLLMENT_DENIED_ERR_CODE "error:AT0025"
#define RSA_2048_PRIVKEY_BYTES 1300 // in PKCS#8 format includes padding
#define AES_256_KEY_BYTES 32

int is_enrollment_denied(const char *err_msg);
int retry_pkam_auth_until_success(atclient *ctx, const char *atsign, const atclient_atkeys *atkeys);
int get_apkam_key(char **key, const char *key_name, atclient_connection *ctx, const char *enrollment_id,
                  const char *atsign);

int main(int argc, char *argv[]) {
  atlogger_set_logging_level(ATLOGGER_LOGGING_LEVEL_INFO);
  int ret = 0;
  char *atsign = NULL, *root_host = NULL, *atkeys_fp = NULL, *otp = NULL, *app_name = NULL, *device_name = NULL,
       *namespaces_str = NULL;
  enroll_namespace_list_t *ns_list = malloc(sizeof(enroll_namespace_list_t));

  char enrollment_id[ENROLL_ID_MAX_LEN];
  char status[ENROLL_STATUS_STRING_MAX_LEN];

  // initialize apkam symmetric key and self encryption key (bytes)
  unsigned char *apkam_symmetric_key_bytes;
  size_t aes256_key_unsigned_char_bytes_size = sizeof(unsigned char) * AES_256_KEY_BYTES;
  apkam_symmetric_key_bytes = malloc(aes256_key_unsigned_char_bytes_size);

  size_t aes_key_base64_size = atchops_base64_encoded_size(aes256_key_unsigned_char_bytes_size);
  size_t aes256_key_unsigned_char_base64_size = sizeof(unsigned char) * aes_key_base64_size;
  unsigned char *apkam_symmetric_key_base64 = malloc(aes256_key_unsigned_char_base64_size);

  // allocate memory for enroll params
  enroll_params_t *ep = malloc(sizeof(enroll_params_t)); // Allocate enrollment params
  // intialize iv used for aes encryption of keys
  unsigned char *iv = malloc(sizeof(unsigned char) * ATCHOPS_IV_BUFFER_SIZE);

  // ensure all the above memory allocations hold
  if (iv == NULL) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "Could not allocate mem for iv buffer\n");
    ret = -1;
    goto exit;
  }
  if (apkam_symmetric_key_bytes == NULL) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "Could not allocate mem for apkam_symmetric_key_bytes buffer\n");
    ret = -1;
    goto exit;
  }
  if (apkam_symmetric_key_base64 == NULL) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "Could not allocate mem for apkam_symmetric_key_base64 buffer\n");
    ret = -1;
    goto exit;
  }
  if (ep == NULL) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "Could not allocate memory for enroll params\n");
    ret = -1;
    goto exit;
  }
  memset(iv, 0, sizeof(unsigned char) * ATCHOPS_IV_BUFFER_SIZE);
  memset(apkam_symmetric_key_bytes, 0, aes256_key_unsigned_char_bytes_size);
  memset(apkam_symmetric_key_base64, 0, aes256_key_unsigned_char_base64_size);
  memset(ep, 0, sizeof(enroll_params_t));

  /*
   * 1. Parse args
   */
  if ((ret = atactivate_parse_args(argc, argv, &atsign, NULL, &otp, &atkeys_fp, &app_name, &device_name,
                                   &namespaces_str, &root_host)) != 0) {
    goto exit;
  }
  // 1.1 if atkeys filepath was not passed through args, build default atkeys file path
  if (atkeys_fp == NULL) {
    if ((ret = atauth_build_atkeys_file_path(&atkeys_fp, atsign)) != 0) {
      atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "Could not build atkeys filepath\n");
      ret = -1;
      goto exit;
    }
  }

  /*
   * 2. Generate APKAM keypair + APKAM Symmetric key
   */
  atclient_atkeys atkeys;
  atclient_atkeys_init(&atkeys);

  // 2.1 Generate APKAM Keypair - RSA2048
  unsigned char *pkam_public_key_base64 = NULL, *pkam_private_key_base64 = NULL;
  if ((ret = atchops_rsa_key_generate_base64(&pkam_public_key_base64, &pkam_private_key_base64)) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "Failed APKAM Keypair Generation\n");
    goto exit;
  }
  // set base64 pkam public and private key in the atkeys struct
  atclient_atkeys_set_pkam_public_key_base64(&atkeys, (const char *)pkam_public_key_base64,
                                             strlen((const char *)pkam_public_key_base64));
  atclient_atkeys_set_pkam_private_key_base64(&atkeys, (const char *)pkam_private_key_base64,
                                              strlen((const char *)pkam_private_key_base64));
  // populate the pkam public/private key bytes in the atkeys struct from base64 format
  atclient_atkeys_populate_pkam_public_key(&atkeys, (const char *)pkam_public_key_base64,
                                           strlen((const char *)pkam_public_key_base64));
  atclient_atkeys_populate_pkam_private_key(&atkeys, (const char *)pkam_private_key_base64,
                                            strlen((const char *)pkam_private_key_base64));

  // 2.2 Generate APKAM Symmetric Key - AES256
  if ((ret = atchops_aes_generate_key(apkam_symmetric_key_bytes, ATCHOPS_AES_256)) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "Failed APKAM SymmetricKey Generation\n");
    goto exit;
  }

  // 2.2.1 base64 encoding the APKAM symmetric key + populate the same into atkeys struct
  size_t apkam_symm_key_base64_len = 0;
  if ((ret = atchops_base64_encode(apkam_symmetric_key_bytes, aes256_key_unsigned_char_bytes_size,
                                   apkam_symmetric_key_base64, aes256_key_unsigned_char_base64_size,
                                   &apkam_symm_key_base64_len)) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "Failed encoding APKAM SymmetricKey to base64\n");
    goto exit;
  }
  atclient_atkeys_set_apkam_symmetric_key_base64(&atkeys, (const char *)apkam_symmetric_key_base64,
                                                 apkam_symm_key_base64_len);

  // 3. Initialize enrollment params + atclient
  if ((ret = atcommons_enroll_namespace_list_from_string(namespaces_str, ns_list)) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "Could not parse namespace string\n");
    goto exit;
  }
  atcommons_enroll_params_init(ep);
  ep->app_name = app_name;
  ep->device_name = device_name;
  ep->ns_list = ns_list;
  ep->apkam_public_key = (unsigned char *)atkeys.pkam_public_key_base64;

  // 3.1 Init atclient
  atclient at_client;
  atclient_init(&at_client);

  // 4. Send enrollment request + retry APKAM auth until the request is approved or denied
  // 4.1 Send onboarding enrollment request
  if ((ret = atauth_send_enroll_request(&at_client, ep, enrollment_id, status)) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atauth_send_enroll_request: %d\n", ret);
    goto exit;
  }
  atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_INFO, "MPKAM enrollment response:\tenrollment_id: %s\tstatus: %s\n",
               enrollment_id, status);
  atclient_atkeys_set_enrollment_id(&atkeys, enrollment_id, strlen(enrollment_id));

  // 4.2 Retry APKAM auth until success
  if ((ret = retry_pkam_auth_until_success(&at_client, atsign, &atkeys)) != 0) {
    goto exit;
  }

  // 4. Fetch APKAM keys from server using get:keys verb
  // 4.1.1 Fetch encrypted default encryption private key
  char *encrypted_def_encryption_privkey_name = "default_enc_private_key";
  char *encrypted_self_encryption_key_name = "default_self_enc_key";
  char *encrypted_default_encryption_private_key = NULL;
  char *encrypted_default_self_encryption_key = NULL;
  if ((ret = get_apkam_key(&encrypted_default_encryption_private_key, encrypted_def_encryption_privkey_name,
                           &at_client.atserver_connection, enrollment_id, atsign)) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "Failed fetching def_encryption_privkey | get_apkam_key: %d", ret);
    ret = 1;
    goto exit;
  }
  // 4.1.2 Fetch encrypted self encryption key
  if ((ret = get_apkam_key(&encrypted_default_self_encryption_key, encrypted_self_encryption_key_name,
                           &at_client.atserver_connection, enrollment_id, atsign)) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "Failed fetching def_encryption_privkey | get_apkam_key: %d", ret);
    ret = 1;
    goto exit;
  }

  // 4.2 decrypt the default encryption private key using apkam symmetric key
  // 4.2.1 convert encrypted default encryption private key to bytes
  unsigned char *encrypted_default_enc_privkey_bytes = NULL;
  size_t encrypted_default_enc_privkey_bytes_len = 0;
  if ((ret = atchops_utf8_encode(encrypted_default_encryption_private_key, &encrypted_default_enc_privkey_bytes,
                                 &encrypted_default_enc_privkey_bytes_len)) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR,
                 "Failed UTF-8 encoding the encrypted_def_encryption_privkey | atchops_utf8_encode: %d\n", ret);
    goto exit;
  }

  // 4.2.2 decrypt the default encryption private key using APKAM symmetruic key
  unsigned char *decrypted_def_enc_privkey = malloc(sizeof(unsigned char) * RSA_2048_PRIVKEY_BYTES);
  size_t decrypted_def_enc_privkey_len = 0;
  if ((ret = atchops_aes_ctr_decrypt(apkam_symmetric_key_bytes, ATCHOPS_AES_256, iv,
                                     encrypted_default_enc_privkey_bytes, encrypted_default_enc_privkey_bytes_len,
                                     decrypted_def_enc_privkey, sizeof(unsigned char) * RSA_2048_PRIVKEY_BYTES,
                                     &decrypted_def_enc_privkey_len)) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR,
                 "Failed decrypting the def_enc_privkey | atchops_aes_ctr_decrypt: %d\n", ret);
    goto exit;
  }

  // 4.2.3 Base64 encode the decrypted default encryption private key
  size_t def_enc_privkey_base64_size = atchops_base64_encoded_size(RSA_2048_PRIVKEY_BYTES);
  size_t def_enc_privkey_base64_len = 0;
  unsigned char *def_encryption_privkey_base64 = malloc(sizeof(char) * def_enc_privkey_base64_size);
  if ((ret = atchops_base64_encode(decrypted_def_enc_privkey, sizeof(decrypted_def_enc_privkey),
                                   def_encryption_privkey_base64, def_enc_privkey_base64_size,
                                   &def_enc_privkey_base64_len)) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR,
                 "Failed base64 encoding the default enc privkey | atchops_base64_encode: %d", ret);
    goto exit;
  }
  atclient_atkeys_set_encrypt_private_key_base64(&atkeys, (const char *)def_encryption_privkey_base64,
                                                 def_enc_privkey_base64_len);

  // 4.3 Decrypt the default self encryption key
  // 4.3.1 Convert the default self encryption key to bytes
  unsigned char *encrypted_self_enc_key_bytes = NULL;
  size_t encrypted_self_enc_key_bytes_len = 0;
  if ((ret = atchops_utf8_encode(encrypted_default_encryption_private_key, &encrypted_self_enc_key_bytes,
                                 &encrypted_self_enc_key_bytes_len)) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR,
                 "Failed UTF-8 encoding the encrypted_self_enc_key | atchops_utf8_encode: %d\n", ret);
    goto exit;
  }

  // 4.3.2 Decrypt the default self encryption key using APKAM symmetric key
  unsigned char *decrypted_self_enc_key = malloc(sizeof(unsigned char) * AES_256_KEY_BYTES);
  size_t decrypted_self_enc_key_len = 0;
  if ((ret = atchops_aes_ctr_decrypt(apkam_symmetric_key_bytes, ATCHOPS_AES_256, iv, encrypted_self_enc_key_bytes,
                                     encrypted_self_enc_key_bytes_len, decrypted_self_enc_key,
                                     sizeof(unsigned char) * AES_256_KEY_BYTES, &decrypted_self_enc_key_len)) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR,
                 "Failed decrypting the self_enc_key | atchops_aes_ctr_decrypt: %d\n", ret);
    goto exit;
  }

  // 4.3.3 Base64 encode the decrypted default self encryption key
  size_t def_self_enc_key_base64_size = atchops_base64_encoded_size(AES_256_KEY_BYTES);
  size_t def_self_enc_key_base64_len = 0;
  unsigned char *def_self_enc_key_base64 = malloc(sizeof(char) * def_self_enc_key_base64_size);
  if ((ret = atchops_base64_encode(decrypted_self_enc_key, sizeof(decrypted_self_enc_key), def_self_enc_key_base64,
                                   def_self_enc_key_base64_size, &def_self_enc_key_base64_len)) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR,
                 "Failed base64 encoding the default self enc key | atchops_base64_encode: %d", ret);
    goto exit;
  }
  atclient_atkeys_set_self_encryption_key_base64(&atkeys, (const char *)def_self_enc_key_base64,
                                                 def_self_enc_key_base64_len);

  // 4.4 Fetch the default encryption public key from server
  atclient_atkey enc_pub_key;
  atclient_atkey_init(&enc_pub_key);
  // 4.4.1 Construct the encryption public atkey
  char *def_enc_pubkey_base64 = NULL;
  if ((ret = atclient_atkey_create_public_key(&enc_pub_key, "publickey", atsign, NULL)) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR,
                 "Failed create enc pub atkey | atclient_atkey_create_public_key: %d\n", ret);
    goto exit;
  }
  // 4.4.2 Fetch the key from server
  atclient_get_public_key_request_options pubkey_opts;
  atclient_get_public_key_request_options_init(&pubkey_opts);
  if ((ret = atclient_get_public_key(&at_client, &enc_pub_key, &def_enc_pubkey_base64, &pubkey_opts)) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "Failed fetching def enc pubkey | atclient_get_public_key: %d\n",
                 ret);
    goto exit;
  }
  atclient_atkeys_set_encrypt_public_key_base64(&atkeys, def_enc_pubkey_base64, strlen(def_enc_pubkey_base64));

  // 5. Write the keys to an atkeys file
  if ((ret = atclient_atkeys_write_to_path(&atkeys, atkeys_fp)) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atclient_atkeys_write_to_path: %d\n", ret);
    ret = 1;
    goto exit;
  }
  atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_INFO, "Success !!!\t Your atKeys file has been generated at \'%s\'\n",
               atkeys_fp);

exit: {
atkeys_fp_exit: { free(atkeys_fp); }
args_exit: {
  free(atsign);
  free(root_host);
}
  free(apkam_symmetric_key_bytes);
  free(apkam_symmetric_key_base64);
  free(ep);
  free(iv);
}
}

int retry_pkam_auth_until_success(atclient *ctx, const char *atsign, const atclient_atkeys *atkeys) {
  int ret = 1;
  atclient_authenticate_options opts;
  atclient_authenticate_options_init(&opts);
  char *err_msg = NULL;

  while (true) {
    ret = atclient_pkam_authenticate(ctx, atsign, atkeys, &opts, &err_msg);
    if (ret == 0) {
      atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_INFO, "enrollment approved | APKAM auth success\n");
      return ret;
    }
    if (is_enrollment_denied(err_msg)) {
      atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "enrollment_id: %s is denied\n", atkeys->enrollment_id);
      ret = 1;
      return ret;
    }
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "APKAM auth failed. Retrying in %d secs\n",
                 DEFAULT_APKAM_RETRY_INTERVAL);
    sleep(DEFAULT_APKAM_RETRY_INTERVAL);
  }
}

// fetches def_encryption_privkey from server which has been encrypted using the current enrollments APKAM symmetric key
// assumes that the atclient instance has a valid authenticated connection
int get_apkam_key(char **key, const char *key_name, atclient_connection *ctx, const char *enrollment_id,
                  const char *atsign) {
  int ret = 0;
  const size_t command_size = strlen("keys:get:keyName:") + ENROLL_ID_MAX_LEN + strlen(key_name) + strlen("__manage") +
                              strlen(atsign) + 5; // +5 for the two '.'s and \r\n\0
  char command[command_size];
  snprintf(command, command_size, "keys:get:keyName:%s.%s.__manage%s\r\n", enrollment_id, key_name, atsign);

  const size_t recv_size = 1000;
  char recv[recv_size];
  size_t recv_len = 0;
  if ((ret = atclient_connection_send(ctx, command, command_size, recv, recv_size, &recv_len)) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atclient_connection_send: %d\n", ret);
    return ret;
  }
  // parse server response json
  const cJSON *json_server_resp = cJSON_Parse(recv);
  if (json_server_resp == NULL) {
    printf("Error parsing server response JSON\n");
    ret = 1;
    return ret;
  }
  // extract the key from the json
  const cJSON *key_json = cJSON_GetObjectItemCaseSensitive(json_server_resp, key_name);
  if (cJSON_IsString(key_json) && key_json->valuestring != NULL) {
    *key = key_json->valuestring;
  }
  return ret;
}

// returns 1 if the error_message contains the ENROLLMENT_DENIED error code, otherwise 0
int is_enrollment_denied(const char *err_msg) {
  return strncmp(err_msg, ENROLLMENT_DENIED_ERR_CODE, strlen(ENROLLMENT_DENIED_ERR_CODE)) == 0 ? 1 : 0;
}
