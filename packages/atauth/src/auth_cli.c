#include "atauth/atauth_constants.h"

#include <atauth/atactivate_arg_parser.h>
#include <atauth/atauth_build_atkeys_file_path.h>
#include <atauth/send_enroll_request.h>
#include <atchops/aes.h>
#include <atchops/aes_ctr.h>
#include <atchops/base64.h>
#include <atchops/iv.h>
#include <atclient/atclient_utils.h>
#include <atclient/constants.h>
#include <atclient/string_utils.h>
#include <atcommons/enroll_status.h>
#include <atlogger/atlogger.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define TAG "auth_cli"

int is_enrollment_denied(const char *err_msg);
int retry_pkam_auth_until_success(atclient *ctx, const char *atsign, const atclient_atkeys *atkeys,
                                  const atclient_authenticate_options *opts);
int get_apkam_key(char *key, unsigned char *iv, const char *key_name, atclient_connection *ctx,
                  const char *enrollment_id, const char *atsign);
int create_new_atserver_connection(atclient *ctx, const char *atsign, const atclient_authenticate_options *options);
int atauth_validate_args(const char *otp, const char *app_name, const char *device_name, const char *namespaces_str);

int main(int argc, char *argv[]) {
  atlogger_set_logging_level(ATLOGGER_LOGGING_LEVEL_INFO);
  int ret = 0, root_port = 0;
  char *atsign_temp = NULL, *root_host = NULL, *atkeys_fp = NULL, *otp = NULL, *app_name = NULL, *device_name = NULL,
       *namespaces_str = NULL;

  char enrollment_id[ENROLL_ID_MAX_LEN];
  char status[ATCOMMONS_ENROLL_STATUS_STRING_MAX_LEN];

  // initialize apkam symmetric key buffer (bytes)
  size_t aes256_key_unsigned_char_bytes_size = sizeof(unsigned char) * ATAUTH_AES_256_KEY_BYTES;
  unsigned char apkam_symmetric_key_bytes[aes256_key_unsigned_char_bytes_size];

  // initialize apkam symmetric key buffer (base64)
  size_t aes_key_base64_size = atchops_base64_encoded_size(aes256_key_unsigned_char_bytes_size);
  size_t aes256_key_unsigned_char_base64_size = sizeof(unsigned char) * aes_key_base64_size;
  unsigned char apkam_symmetric_key_base64[aes256_key_unsigned_char_base64_size];

  // init buffer to hold apkam symmetric key that is encrypted using at_server's default encryption public key (bytes)
  const size_t rsa_2048_ciphertext_size = 256;
  unsigned char encrypted_apkam_symmetric_key_bytes[rsa_2048_ciphertext_size];

  // init buffer to hold apkam symmetric key that is encrypted using at_server's default encryption public key (base64)
  const size_t base64_encoded_rsa2048_ciphertext_size = atchops_base64_encoded_size(rsa_2048_ciphertext_size);
  unsigned char *encrypted_apkam_symmetric_key_base64[base64_encoded_rsa2048_ciphertext_size];

  // init buffer to hold encrypted default encryption private key received from server
  const size_t rsa_2048_privkey_base64_len = atchops_base64_encoded_size(ATAUTH_RSA_2048_PRIVKEY_BYTES);
  const size_t aes256_encrypted_rsa_privkey_size = atchops_aes_ctr_ciphertext_size(
      rsa_2048_privkey_base64_len); // size for an AES256 encrypted RSA2048 privkey in bytes
  const size_t aes256_encrypted_rsa_privkey_base64_size =
      atchops_base64_encoded_size(aes256_encrypted_rsa_privkey_size);
  char encrypted_default_encryption_private_key[aes256_encrypted_rsa_privkey_base64_size];

  // init buffer to hold encrypted default self encryption key received from server
  const size_t aes256_encrypted_aes_key_base64_size =
      atchops_base64_encoded_size(atchops_aes_ctr_ciphertext_size(ATCHOPS_AES_256));
  char encrypted_default_self_encryption_key[aes256_encrypted_aes_key_base64_size];

  // init buffers to hold IVs for encrypted self enc key and enc private key received from server
  size_t base64_encoded_iv_size = atchops_base64_encoded_size(ATCHOPS_IV_BUFFER_SIZE);
  unsigned char enc_privkey_iv[base64_encoded_iv_size];  // base64 encoded iv
  unsigned char self_enc_key_iv[base64_encoded_iv_size]; // base64 encoded iv

  memset(apkam_symmetric_key_bytes, 0, aes256_key_unsigned_char_bytes_size);
  memset(apkam_symmetric_key_base64, 0, aes256_key_unsigned_char_base64_size);
  memset(encrypted_apkam_symmetric_key_bytes, 0, rsa_2048_ciphertext_size);
  memset(encrypted_apkam_symmetric_key_base64, 0, base64_encoded_rsa2048_ciphertext_size);
  memset(encrypted_default_encryption_private_key, 0, aes256_encrypted_rsa_privkey_base64_size);
  memset(encrypted_default_self_encryption_key, 0, aes256_encrypted_aes_key_base64_size);
  memset(enc_privkey_iv, 0, base64_encoded_iv_size);
  memset(self_enc_key_iv, 0, base64_encoded_iv_size);
  memset(enrollment_id, 0, sizeof(enrollment_id));

  /*
   * 1. Parse + validate command-line arguments
   */
  if ((ret = atactivate_parse_args(argc, argv, &atsign_temp, NULL, &otp, &atkeys_fp, &app_name, &device_name,
                                   &namespaces_str, &root_host, &root_port)) != 0) {
    goto exit;
  }

  // 1.1 Validate arguments
  if ((ret = atauth_validate_args(otp, app_name, device_name, namespaces_str)) != 0) {
    goto exit;
  }

  // 1.2 Ensure atsign starts with '@'
  char *atsign = NULL;
  if ((ret = atclient_string_utils_atsign_with_at(atsign_temp, &atsign)) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atclient_string_utils_atsign_with_at: %d\n", ret);
    goto exit;
  }
  free(atsign_temp); // no longer needed

  // 1.3 if atkeys filepath was not passed through args, build default atkeys file path
  if (atkeys_fp == NULL) {
    if ((ret = atauth_build_atkeys_file_path(&atkeys_fp, atsign)) != 0) {
      atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "Could not build atkeys filepath\n");
      ret = -1;
      goto args_exit;
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
    goto atkeys_fp_exit;
  }
  // 2.1.1 set base64 pkam public and private key in the atkeys struct
  atclient_atkeys_set_pkam_public_key_base64(&atkeys, (const char *)pkam_public_key_base64,
                                             strlen((const char *)pkam_public_key_base64));
  atclient_atkeys_set_pkam_private_key_base64(&atkeys, (const char *)pkam_private_key_base64,
                                              strlen((const char *)pkam_private_key_base64));

  // 2.1.2 populate the pkam public/private key bytes in the atkeys struct by parsing the base64 encoded keys
  atclient_atkeys_populate_pkam_public_key(&atkeys, (const char *)pkam_public_key_base64,
                                           strlen((const char *)pkam_public_key_base64));
  atclient_atkeys_populate_pkam_private_key(&atkeys, (const char *)pkam_private_key_base64,
                                            strlen((const char *)pkam_private_key_base64));

  // 2.2 Init atclient
  atclient_authenticate_options opts;
  atclient_authenticate_options_init(&opts);
  atclient_authenticate_options_set_atdirectory_host(&opts, root_host);
  atclient_authenticate_options_set_atdirectory_port(&opts, root_port);

  atclient at_client;
  atclient_init(&at_client);

  // 2.2.1 Start new connection
  if ((ret = create_new_atserver_connection(&at_client, atsign, &opts)) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_DEBUG, "create_new_atserver_connection: %d\n", ret);
    goto pkam_pub_keys_exit;
  }

  // 2.3 Fetch the default encryption public key from server
  atclient_atkey enc_pub_key;
  atclient_atkey_init(&enc_pub_key);

  // 2.3.1 Construct the encryption public atkey
  char *enc_pubkey_base64 = NULL;
  if ((ret = atclient_atkey_create_public_key(&enc_pub_key, "publickey", atsign, NULL)) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR,
                 "Failed create enc pub atkey | atclient_atkey_create_public_key: %d\n", ret);
    goto pkam_pub_keys_exit;
  }

  // 2.3.2 Fetch the key from server
  atclient_get_public_key_request_options pubkey_opts;
  atclient_get_public_key_request_options_init(&pubkey_opts);
  if ((ret = atclient_get_public_key(&at_client, &enc_pub_key, &enc_pubkey_base64, &pubkey_opts)) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "Failed fetching def enc pubkey | atclient_get_public_key: %d\n",
                 ret);
    goto enc_pub_key_exit;
  }
  atclient_atkeys_set_encrypt_public_key_base64(&atkeys, enc_pubkey_base64, strlen(enc_pubkey_base64));

  // 2.3.3 Parse base64 encoded Default Encryption PubKey into an atchops_rsa_key_public_key struct
  atchops_rsa_key_public_key encrypt_public_key;
  atchops_rsa_key_public_key_init(&encrypt_public_key);
  if ((ret = atchops_rsa_key_populate_public_key(&encrypt_public_key, enc_pubkey_base64, strlen(enc_pubkey_base64))) !=
      0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR,
                 "Failed parsing encryption_public_key | atchops_rsa_key_populate_public_key: %d\n", ret);
    goto enc_pub_key_exit;
  }

  // 2.4 Generate APKAM Symmetric Key - AES256
  if ((ret = atchops_aes_generate_key(apkam_symmetric_key_bytes, ATCHOPS_AES_256)) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "Failed APKAM SymmetricKey Generation\n");
    goto enc_pub_key_exit;
  }

  // 2.4.1 base64 encoding the APKAM symmetric key + populate the same into atkeys struct
  size_t apkam_symmetric_key_base64_len = 0;
  if ((ret = atchops_base64_encode(apkam_symmetric_key_bytes, aes256_key_unsigned_char_bytes_size,
                                   apkam_symmetric_key_base64, aes256_key_unsigned_char_base64_size,
                                   &apkam_symmetric_key_base64_len)) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "Failed encoding APKAM SymmetricKey to base64\n");
    goto enc_pub_key_exit;
  }
  atclient_atkeys_set_apkam_symmetric_key_base64(&atkeys, (const char *)apkam_symmetric_key_base64, apkam_symmetric_key_base64_len);

  // 2.5 Encrypt APKAM Symmetric Key using Default Encryption PublicKey
  if ((ret = atchops_rsa_encrypt(&encrypt_public_key, apkam_symmetric_key_base64, apkam_symmetric_key_base64_len,
                                 encrypted_apkam_symmetric_key_bytes)) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR,
                 "Failed RSA2048 encrypting apkam symmetric key | atchops_rsa_encrypt: %d\n", ret);
    goto enc_pub_key_exit;
  }

  // 2.5.1 base64 encode the encrypted APKAM symmetric key
  size_t encrypted_apkam_symmetric_key_base64_len = 0;
  if ((ret = atchops_base64_encode(encrypted_apkam_symmetric_key_bytes, rsa_2048_ciphertext_size,
                                   (unsigned char *)encrypted_apkam_symmetric_key_base64, base64_encoded_rsa2048_ciphertext_size,
                                   &encrypted_apkam_symmetric_key_base64_len)) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR,
                 "Failed base64 encoding encrypted_apkam_symmetric_key | atchops_base64_encode: %d\n", ret);
    goto enc_pub_key_exit;
  }

  /*
   * 3. Construct enroll params + send enrollment requset
   */
  // 3.1 Initialize and populate enrollment params structs
  atcommons_enroll_namespace_list_t *ns_list = malloc(sizeof(atcommons_enroll_namespace_list_t));
  if ((ret = atcommmons_init_enroll_namespace_list(ns_list)) != 0) {
    goto enc_pub_key_exit;
  }

  // 3.1.1 parse namespace list string passed through command-line args
  if ((ret = atcommons_enroll_namespace_list_from_string(&ns_list, namespaces_str)) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "Could not parse namespace string\n");
    goto ns_list_exit;
  }

  // 3.1.2 init enroll params struct and populate
  atcommons_enroll_params_t ep;
  atcommons_enroll_params_init(&ep);
  ep.app_name = app_name;
  ep.device_name = device_name;
  ep.otp = otp;
  ep.ns_list = ns_list;
  ep.apkam_public_key = (unsigned char *)atkeys.pkam_public_key_base64;
  ep.encrypted_apkam_symmetric_key = (unsigned char *)encrypted_apkam_symmetric_key_base64;

  // 3.2 Send enrollment request
  if ((ret = atauth_send_enroll_request(&at_client, &ep, enrollment_id, status)) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atauth_send_enroll_request: %d\n", ret);
    goto exit;
  }
  atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_INFO, "Enrollment Response: enrollment_id: %s\tstatus: %s\n", enrollment_id,
               status);
  atclient_atkeys_set_enrollment_id(&atkeys, enrollment_id, strlen(enrollment_id));

  // 3.2 Retry APKAM auth until success
  if ((ret = retry_pkam_auth_until_success(&at_client, atsign, &atkeys, &opts)) != 0) {
    goto ns_list_exit;
  }

  /*
   * 4. Fetch APKAM keys from server using get:keys verb and decrypt them (keys are encrypted with APKAM SymmetricKey)
   */
  unsigned char *enc_privkey_iv_base64_decoded = NULL, *self_enc_key_iv_base64_decoded = NULL;

  // 4.1.1 Fetch encrypted default encryption private key
  if ((ret = get_apkam_key(encrypted_default_encryption_private_key, enc_privkey_iv,
                           ATAUTH_ENCRYPTED_DEFAULT_ENC_PRIVKEY_NAME, &at_client.atserver_connection, enrollment_id,
                           atsign)) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "Failed fetching Default encryption_privkey | get_apkam_key: %d\n",
                 ret);
    ret = 1;
    goto ns_list_exit;
  }

  // 4.1.2 Fetch encrypted self encryption key
  if ((ret = get_apkam_key(encrypted_default_self_encryption_key, self_enc_key_iv, ATAUTH_ENCRYPTED_SELF_ENC_KEY_NAME,
                           &at_client.atserver_connection, enrollment_id, atsign)) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "Failed fetching Default self encryption key | get_apkam_key: %d\n",
                 ret);
    ret = 1;
    goto ns_list_exit;
  }

  // 4.2 Decrypt the default encryption private key using apkam symmetric key
  // 4.2.1 base64 decode the encrypted DefaultEncryptionPrivateKey
  const size_t encrypted_default_encryption_private_key_len = strlen(encrypted_default_encryption_private_key);
  size_t encrypted_default_enc_privkey_base64_decoded_size =
      atchops_base64_decoded_size(encrypted_default_encryption_private_key_len);
  size_t encrypted_default_enc_privkey_base64_decoded_len = 0;

  unsigned char *encrypted_default_enc_privkey_base64_decoded =
      malloc(sizeof(unsigned char) * encrypted_default_enc_privkey_base64_decoded_size);
  if (encrypted_default_enc_privkey_base64_decoded == NULL) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR,
                 "Unable to allocate memory for encrypted_default_enc_privkey_base64_decoded\n");
    goto ns_list_exit;
  }
  memset(encrypted_default_enc_privkey_base64_decoded, 0,
         encrypted_default_enc_privkey_base64_decoded_size);

  if ((ret =
           atchops_base64_decode((unsigned char *)encrypted_default_encryption_private_key, encrypted_default_encryption_private_key_len,
                                 encrypted_default_enc_privkey_base64_decoded,
                                 encrypted_default_enc_privkey_base64_decoded_size,
                                 &encrypted_default_enc_privkey_base64_decoded_len)) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR,
                 "Failed base64 decoding encrypted_default_enc_privkey | atchops_base64_decode: %d\n", ret);
    goto decrypted_enc_privkeykey_exit;
  }

  // 4.2.2 base64 decode the encryption private key IV if received from server (base64 decoding not required when using
  // legacy IV)
  size_t enc_privkey_iv_base64_decoded_len = 0;

  enc_privkey_iv_base64_decoded = malloc(sizeof(unsigned char) * ATCHOPS_IV_BUFFER_SIZE);
  if (enc_privkey_iv_base64_decoded == NULL) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "Unable to allocate memory for enc_privkey_iv_base64_decoded\n");
    goto decrypted_enc_privkeykey_exit;
  }
  memset(enc_privkey_iv_base64_decoded, 0, ATCHOPS_IV_BUFFER_SIZE);

  if ((ret = atchops_base64_decode(enc_privkey_iv, strlen((char *)enc_privkey_iv), enc_privkey_iv_base64_decoded,
                                   ATCHOPS_IV_BUFFER_SIZE, &enc_privkey_iv_base64_decoded_len)) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR,
                 "Failed base64 decoding the enc privkey iv received from server | atchops_base64_decode: %d\n", ret);
    ret = 1;
    goto encrypted_enc_privkey_base64_decoded_exit;
  }

  // 4.2.3 decrypt the default encryption private key using APKAM symmetric key
  size_t decypted_def_enc_privkey_size =
      atchops_aes_ctr_plaintext_size(encrypted_default_enc_privkey_base64_decoded_len);
  unsigned char *decrypted_def_enc_privkey = malloc(sizeof(unsigned char) * decypted_def_enc_privkey_size);

  if (decrypted_def_enc_privkey == NULL) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "Unable to allocate memory for decrypted_def_enc_privkey\n");
    goto exit;
  }
  memset(decrypted_def_enc_privkey, 0, sizeof(unsigned char) * decypted_def_enc_privkey_size);
  size_t decrypted_def_enc_privkey_len = 0;

  if ((ret = atchops_aes_ctr_decrypt(apkam_symmetric_key_bytes, ATCHOPS_AES_256, enc_privkey_iv_base64_decoded,
                                     encrypted_default_enc_privkey_base64_decoded,
                                     encrypted_default_enc_privkey_base64_decoded_len, decrypted_def_enc_privkey,
                                     decypted_def_enc_privkey_size, &decrypted_def_enc_privkey_len)) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR,
                 "Failed decrypting the def_enc_privkey | atchops_aes_ctr_decrypt: %d\n", ret);
    goto decrypted_enc_privkeykey_exit;
  }

  atclient_atkeys_set_encrypt_private_key_base64(&atkeys, (const char *)decrypted_def_enc_privkey,
                                                 decrypted_def_enc_privkey_len);

  // 4.3 Decrypt the default self encryption key
  // 4.3.1 base64 decode the default self encryption key
  size_t encrypted_default_self_enc_key_len = strlen(encrypted_default_self_encryption_key);
  size_t encrypted_default_self_enc_key_base64_decoded_size =
      atchops_base64_decoded_size(encrypted_default_self_enc_key_len);
  size_t encrypted_self_enc_key_base64_decoded_len = 0;
  unsigned char *encrypted_self_enc_key_base64_decoded =
      malloc(sizeof(unsigned char) * encrypted_default_self_enc_key_base64_decoded_size);
  if (encrypted_self_enc_key_base64_decoded == NULL) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR,
                 "Unable to allocate memory for encrypted_self_enc_key_base64_decoded\n");
    goto decrypted_enc_privkeykey_exit;
  }
  memset(encrypted_self_enc_key_base64_decoded, 0,
         sizeof(unsigned char) * encrypted_default_self_enc_key_base64_decoded_size);

  if ((ret = atchops_base64_decode((unsigned char *)encrypted_default_self_encryption_key,
                                   encrypted_default_self_enc_key_len, encrypted_self_enc_key_base64_decoded,
                                   sizeof(unsigned char) * encrypted_default_self_enc_key_base64_decoded_size,
                                   &encrypted_self_enc_key_base64_decoded_len)) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR,
                 "Failed base64 decoding the encrypted_self_enc_key | atchops_base64_decode: %d\n", ret);
    goto self_enc_key_base64_decoded_exit;
  }

  // 4.3.2 base64 decode the self encryption key IV if received from server
  // base64 decoding not required when using legacy IV
  size_t self_enc_key_iv_base64_decoded_size = ATCHOPS_IV_BUFFER_SIZE;
  size_t self_enc_key_iv_base64_decoded_len = 0;
  self_enc_key_iv_base64_decoded = malloc(sizeof(char) * ATCHOPS_IV_BUFFER_SIZE);
  if (self_enc_key_iv_base64_decoded == NULL) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "Unable to allocate memory for self_enc_key_iv_base64_decoded\n");
    goto self_enc_key_base64_decoded_exit;
  }
  memset(self_enc_key_iv_base64_decoded, 0, self_enc_key_iv_base64_decoded_size);

  if ((ret = atchops_base64_decode(self_enc_key_iv, strlen((char *)self_enc_key_iv), self_enc_key_iv_base64_decoded,
                                   self_enc_key_iv_base64_decoded_size, &self_enc_key_iv_base64_decoded_len)) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR,
                 "Failed base64 decoding the self_enc_key iv received from server | atchops_base64_decode: %d\n", ret);
    ret = 1;
    goto self_enc_key_base64_decoded_exit;
  }

  // 4.3.3 Decrypt the default self encryption key using APKAM symmetric key
  size_t decrypted_self_enc_key_size = atchops_aes_ctr_plaintext_size(encrypted_self_enc_key_base64_decoded_len);
  unsigned char *decrypted_self_enc_key = malloc(sizeof(unsigned char) * decrypted_self_enc_key_size);

  if (decrypted_self_enc_key == NULL) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "Unable to allocate memory for decrypted_self_enc_key\n");
    goto exit;
  }

  size_t decrypted_self_enc_key_len = 0;
  if ((ret = atchops_aes_ctr_decrypt(apkam_symmetric_key_bytes, ATCHOPS_AES_256, self_enc_key_iv_base64_decoded,
                                     encrypted_self_enc_key_base64_decoded, encrypted_self_enc_key_base64_decoded_len,
                                     decrypted_self_enc_key, decrypted_self_enc_key_size,
                                     &decrypted_self_enc_key_len)) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR,
                 "Failed decrypting the self_enc_key | atchops_aes_ctr_decrypt: %d\n", ret);
    goto decrypted_self_enc_key_exit;
  }
  // set the decrypted self encryption key in the atkeys struct
  // Note: base64 encoding the key is not required as the key is base64 encoded on the server side before encryption
  atclient_atkeys_set_self_encryption_key_base64(&atkeys, (const char *)decrypted_self_enc_key,
                                                 decrypted_self_enc_key_len);

  /*
   * 5. Write the keys to an atkeys file
   */
  if ((ret = atclient_atkeys_write_to_path(&atkeys, atkeys_fp)) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atclient_atkeys_write_to_path: %d\n", ret);
    ret = 1;
    goto ns_list_exit;
  }
  atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_INFO, "Success !!!\t Your atKeys file has been generated at \'%s\'\n",
               atkeys_fp);

  // exits
decrypted_self_enc_key_exit: { free(decrypted_self_enc_key); }
self_enc_key_base64_decoded_exit: { free(encrypted_self_enc_key_base64_decoded); }
decrypted_enc_privkeykey_exit: { free(decrypted_def_enc_privkey); }
encrypted_enc_privkey_base64_decoded_exit: { free(encrypted_default_enc_privkey_base64_decoded); }
ns_list_exit: { free(ns_list); }
enc_pub_key_exit: { free(enc_pubkey_base64); }
pkam_pub_keys_exit: {
  free(pkam_public_key_base64);
  free(pkam_private_key_base64);
}
atkeys_fp_exit: { free(atkeys_fp); }
args_exit: {
  free(atsign);
  free(root_host);
  free(app_name);
  free(device_name);
  free(otp);
  free(namespaces_str);
}
exit: {
  if (ret != 0)
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "Aborting with exit code: %d\n", ret);

  exit(ret);
}
}

// retries APKAM auth using the set of atkeys provided until the authentication succeeds
// sleeps `ATAUTH_DEFAULT_APKAM_RETRY_INTERVAL` seconds after each attempt
int retry_pkam_auth_until_success(atclient *ctx, const char *atsign, const atclient_atkeys *atkeys,
                                  const atclient_authenticate_options *opts) {
  int ret = 1;
  char *err_msg;

  while (true) {
    ret = atclient_pkam_authenticate(ctx, atsign, atkeys, (atclient_authenticate_options *)opts, &err_msg);

    if (ret == 0) {
      atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_INFO, "enrollment approved | APKAM auth success\n");
      return ret;
    }

    if (err_msg != NULL && is_enrollment_denied(err_msg)) {
      atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "enrollment_id: %s is denied\n", atkeys->enrollment_id);
      ret = 1;
      return ret;
    }
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "APKAM auth failed. Retrying in %d secs\n",
                 ATAUTH_DEFAULT_APKAM_RETRY_INTERVAL);
    sleep(ATAUTH_DEFAULT_APKAM_RETRY_INTERVAL);
  }
}

/** Fetches enrollment specific keys from server which has been encrypted using the current enrollment's APKAM
 * SymmetricKey
 *
 * Note: It is assumed that the atclient instance has a valid authenticated connection.
 */
int get_apkam_key(char *key, unsigned char *iv, const char *key_name, atclient_connection *ctx,
                  const char *enrollment_id, const char *atsign) {
  int ret = 0;
  // Calculate command length
  const size_t cmd_size =
      snprintf(NULL, 0, "keys:get:keyName:%s.%s.__manage%s\r\n", enrollment_id, key_name, atsign) + 1;
  char command[cmd_size];

  // Construct command
  snprintf(command, cmd_size, "keys:get:keyName:%s.%s.__manage%s\r\n", enrollment_id, key_name, atsign);
  const size_t recv_size = 2400;
  unsigned char recv[recv_size];
  memset(recv, 0, sizeof(char) * recv_size);
  size_t recv_len = 0;
  if ((ret = atclient_connection_send(ctx, (unsigned char *)command, strlen(command), recv, recv_size, &recv_len)) !=
      0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atclient_connection_send: %d\n", ret);
    return ret;
  }

  // Parse response
  char *response_trimmed = NULL;
  // below method points the response_trimmed variable to the position of 'data:' substring
  if (atclient_string_utils_get_substring_position((char *)recv, ATCLIENT_DATA_TOKEN, &response_trimmed) != 0) {
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
  // extract the key from the json
  const cJSON *key_json = cJSON_GetObjectItemCaseSensitive(json_server_resp, "value");
  if (cJSON_IsString(key_json) && key_json->valuestring != NULL) {
    strcpy(key, key_json->valuestring);
  }
  const cJSON *iv_json = cJSON_GetObjectItemCaseSensitive(json_server_resp, "iv");
  if (cJSON_IsString(iv_json) && iv_json->valuestring != NULL) {
    strcpy((char *)iv, iv_json->valuestring);
  }

exit: {
  cJSON_Delete(json_server_resp);
  return ret;
}
}

// returns 1 if the error_message contains the ENROLLMENT_DENIED error code, otherwise 0
int is_enrollment_denied(const char *err_msg) {
  return strncmp(err_msg, ATAUTH_ENROLLMENT_DENIED_ERR_CODE, strlen(ATAUTH_ENROLLMENT_DENIED_ERR_CODE)) == 0;
}

int create_new_atserver_connection(atclient *ctx, const char *atsign, const atclient_authenticate_options *options) {
  char *atserver_host = NULL;
  int atserver_port = 0, ret = 0;

  if (atserver_host == NULL || atserver_port == 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_INFO, "Fetching secondary server address for atsign: %s\n", atsign);
    if ((ret = atclient_utils_find_atserver_address(options->atdirectory_host, options->atdirectory_port, atsign,
                                                    &atserver_host, &atserver_port)) != 0) {
      atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_DEBUG, "atclient_utils_find_atserver_address: %d\n", ret);
      atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR,
                   "Could not fetch secondary address for atsign: %s on root directory: %s:%d\n", atsign,
                   options->atdirectory_host, options->atdirectory_port);
      goto exit;
    }
  }

  if ((ret = atclient_start_atserver_connection(ctx, atserver_host, atserver_port)) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_DEBUG, "atclient_start_atserver_connection: %d\n", ret);
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "Could not connect to secondary server at %s:%d\n", atserver_host,
                 atserver_port);
  }

exit: { return ret; }
}

int atauth_validate_args(const char *otp, const char *app_name, const char *device_name, const char *namespaces_str) {
  int ret = 0;
  if (otp == NULL) {
    ret = 1;
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "otp cannot be NULL\n");
    goto exit;
  }

  if (app_name == NULL) {
    ret = 1;
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "app_name cannot be NULL\n");
    goto exit;
  }

  if (device_name == NULL) {
    ret = 1;
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "device_name cannot be NULL\n");
    goto exit;
  }

  if (namespaces_str == NULL) {
    ret = 1;
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "namespaces_str cannot be NULL\n");
  }

exit: { return ret; }
}
