#include "atauth/atactivate_arg_parser.h"
#include "atauth/atauth_build_atkeys_file_path.h"
#include "atauth/atauth_constants.h"
#include "atchops/base64.h"
#include "atclient/atclient.h"
#include "atclient/atkeys.h"
#include "atclient/connection.h"
#include <atauth/send_enroll_request.h>
#include <atchops/aes.h>
#include <atchops/aes_ctr.h>
#include <atchops/iv.h>
#include <atcommons/enroll_status.h>
#include <atlogger/atlogger.h>

#include <atclient/string_utils.h>
#include <stdlib.h>
#include <string.h>

#define TAG "activate_cli"

int main(int argc, char *argv[]) {
  int ret = 0;
  char *atsign_temp = NULL, *cram_secret = NULL, *root_host = NULL, *atkeys_fp = NULL, *otp = NULL;
  int root_port = 0;
  char enrollment_id[ENROLL_ID_MAX_LEN];
  char status[ATCOMMONS_ENROLL_STATUS_STRING_MAX_LEN];

  // intialize iv used for aes encryption of keys
  unsigned char *iv = malloc(sizeof(unsigned char) * ATCHOPS_IV_BUFFER_SIZE);

  // initialize apkam symmetric key and self encryption key (bytes)
  unsigned char *self_encryption_key_bytes, *apkam_symmetric_key_bytes;
  size_t aes256_key_unsigned_char_bytes_size = sizeof(unsigned char) * ATAUTH_AES_256_KEY_BYTES;
  self_encryption_key_bytes = malloc(aes256_key_unsigned_char_bytes_size);
  apkam_symmetric_key_bytes = malloc(aes256_key_unsigned_char_bytes_size);

  // initialize base64 encoded apkam symmetric key and self encryption key
  size_t aes_key_base64_size = atchops_base64_encoded_size(aes256_key_unsigned_char_bytes_size);
  size_t aes256_key_unsigned_char_base64_size = sizeof(unsigned char) * aes_key_base64_size;
  unsigned char *self_encryption_key_base64 = malloc(aes256_key_unsigned_char_base64_size);
  unsigned char *apkam_symmetric_key_base64 = malloc(aes256_key_unsigned_char_base64_size);

  // intialize encrypted APKAM symmetric Key and encrypted default encryption private key (bytes)
  const size_t rsa_2048_privkey_base64_len = atchops_base64_encoded_size(ATAUTH_RSA_2048_PRIVKEY_BYTES);
  const size_t aes256_encrypted_rsa_privkey_size = atchops_aes_ctr_ciphertext_size(
      rsa_2048_privkey_base64_len); // size for an AES256 encrypted RSA2048 privkey in bytes
  const size_t aes256_encrypted_rsa_privkey_unsigned_char_size =
      sizeof(unsigned char) * aes256_encrypted_rsa_privkey_size;
  const size_t aes256_encrypted_aes256_key_size = atchops_aes_ctr_ciphertext_size(
      aes_key_base64_size); // size of AES256 key encrypted with another AES256 key(bytes)
  const size_t aes256_encrypted_aes256_key_unsigned_char_size =
      sizeof(unsigned char) * aes256_encrypted_aes256_key_size;
  unsigned char *encrypted_default_encryption_private_key_bytes =
      malloc(aes256_encrypted_rsa_privkey_unsigned_char_size);
  unsigned char *encrypted_self_encryption_key_bytes = malloc(aes256_encrypted_aes256_key_unsigned_char_size);

  // intialize base64 encoded encrypted APKAM symmetric Key and encrypted default encryption private key
  const size_t aes256_encrypted_rsa_2048_privkey_base64_len = atchops_base64_encoded_size(rsa_2048_privkey_base64_len);
  const size_t aes256_encrypted_aes_key_base64_len =
      atchops_base64_encoded_size(atchops_base64_encoded_size(ATCHOPS_AES_256));
  unsigned char *encrypted_self_encryption_key_base64 =
      malloc(sizeof(unsigned char) * aes256_encrypted_aes_key_base64_len);
  unsigned char *encrypted_default_encryption_private_key_base64 =
      malloc(sizeof(unsigned char) * aes256_encrypted_rsa_2048_privkey_base64_len);

  // allocate memory for enroll params
  atcommons_enroll_params_t *ep = malloc(sizeof(atcommons_enroll_params_t)); // Allocate enrollment params

  // ensure all the above memory allocations hold
  if (iv == NULL) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "Could not allocate mem for iv buffer\n");
    ret = -1;
    goto exit;
  }
  if (self_encryption_key_bytes == NULL) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "Could not allocate mem for self_encryption_key_bytes buffer\n");
    ret = -1;
    goto iv_exit;
  }
  if (apkam_symmetric_key_bytes == NULL) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "Could not allocate mem for apkam_symmetric_key_bytes buffer\n");
    ret = -1;
    goto self_enc_key_bytes_exit;
  }
  if (self_encryption_key_base64 == NULL) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "Could not allocate mem for self_encryption_key_base64 buffer\n");
    ret = -1;
    goto aes_keys_bytes_exit;
  }
  if (apkam_symmetric_key_base64 == NULL) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "Could not allocate mem for apkam_symmetric_key_base64 buffer\n");
    ret = -1;
    goto aes_keys_bytes_exit;
  }
  if (encrypted_default_encryption_private_key_bytes == NULL) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR,
                 "Could not allocate mem for encrypted_default_encryption_private_key buffer\n");
    ret = -1;
    goto aes_keys_bytes_exit;
  }
  if (encrypted_self_encryption_key_bytes == NULL) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR,
                 "Could not allocate mem for encrypted_self_encryption_key buffer\n");
    ret = -1;
    goto enc_def_enc_privkey_exit;
  }
  if (encrypted_default_encryption_private_key_base64 == NULL) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR,
                 "Could not allocate mem for encrypted_default_encryption_private_key_base64 buffer\n");
    ret = -1;
    goto enc_self_enc_key_exit;
  }
  if (encrypted_self_encryption_key_base64 == NULL) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR,
                 "Could not allocate mem for encrypted_self_encryption_key_base64 buffer\n");
    ret = -1;
    goto enc_def_enc_privkey_base64_exit;
  }
  if (ep == NULL) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "Could not allocate memory for enroll params\n");
    ret = -1;
    goto enc_self_enc_key_base64_exit;
  }

  memset(iv, 0, sizeof(unsigned char) * ATCHOPS_IV_BUFFER_SIZE);
  memset(self_encryption_key_bytes, 0, aes256_key_unsigned_char_bytes_size);
  memset(apkam_symmetric_key_bytes, 0, aes256_key_unsigned_char_bytes_size);
  memset(self_encryption_key_base64, 0, aes256_key_unsigned_char_base64_size);
  memset(apkam_symmetric_key_base64, 0, aes256_key_unsigned_char_base64_size);
  memset(encrypted_default_encryption_private_key_bytes, 0, aes256_encrypted_rsa_privkey_unsigned_char_size);
  memset(encrypted_self_encryption_key_bytes, 0, aes256_encrypted_aes256_key_unsigned_char_size);
  memset(encrypted_default_encryption_private_key_base64, 0,
         sizeof(unsigned char) * aes256_encrypted_rsa_2048_privkey_base64_len);
  memset(encrypted_self_encryption_key_base64, 0, sizeof(unsigned char) * aes256_encrypted_aes_key_base64_len);
  memset(ep, 0, sizeof(atcommons_enroll_params_t));

  /*
   * 1. Parse args
   */
  if ((ret = atactivate_parse_args(argc, argv, &atsign_temp, &cram_secret, &otp, &atkeys_fp, NULL, NULL, NULL,
                                   &root_host, &root_port)) != 0) {
    goto exit;
  }

  // 1.1 Ensure atsign starts with '@'
  char *atsign = NULL;
  if ((ret = atclient_string_utils_atsign_with_at(atsign_temp, &atsign)) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atclient_string_utils_atsign_with_at: %d\n", ret);
    goto exit;
  }
  free(atsign_temp); // no longer needed

  // 1.2 if atkeys filepath was not passed through args, build default atkeys file path
  if (atkeys_fp == NULL) {
    if ((ret = atauth_build_atkeys_file_path(&atkeys_fp, atsign)) != 0) {
      atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "Could not build atkeys filepath\n");
      ret = -1;
      goto args_exit;
    }
  }

  /*
   * 2. init atclient and CRAM auth
   */
  atclient at_client;
  atclient_init(&at_client);

  atclient_authenticate_options options;
  atclient_authenticate_options_init(&options);

  if ((ret = atclient_cram_authenticate(&at_client, atsign, cram_secret, &options)) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "CRAM authentication failed\n");
    goto atclient_exit;
  }

  /*
   * 3. Generate APKAM keypair + Default Encryption Keypair + Self encryption key + APKAM Symmetric Key
   */
  atclient_atkeys atkeys;
  atclient_atkeys_init(&atkeys);

  // 3.1 Generate APKAM Keypair - RSA2048
  unsigned char *pkam_public_key_base64 = NULL, *pkam_private_key_base64 = NULL;
  if ((ret = atchops_rsa_key_generate_base64(&pkam_public_key_base64, &pkam_private_key_base64)) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "Failed APKAM Keypair Generation\n");
    goto atkeys_free_exit;
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

  // 3.2 Generate Default Encryption Keypair - RSA2048
  unsigned char *encrypt_public_key_base64 = NULL, *encrypt_private_key_base64 = NULL;
  if ((ret = atchops_rsa_key_generate_base64(&encrypt_public_key_base64, &encrypt_private_key_base64)) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "Failed Default Encryption Keypair Generation\n");
    goto pkam_keypair_free_exit;
  }
  // sets base64 public and private key in the atkeys struct
  atclient_atkeys_set_encrypt_public_key_base64(&atkeys, (const char *)encrypt_public_key_base64,
                                                strlen((const char *)encrypt_public_key_base64));
  atclient_atkeys_set_encrypt_private_key_base64(&atkeys, (const char *)encrypt_private_key_base64,
                                                 strlen((const char *)encrypt_private_key_base64));
  // populate the encryption public/private key bytes in the atkeys struct from base64 format
  atclient_atkeys_populate_encrypt_public_key(&atkeys, (const char *)encrypt_public_key_base64,
                                              strlen((const char *)encrypt_public_key_base64));
  atclient_atkeys_populate_encrypt_private_key(&atkeys, (const char *)encrypt_private_key_base64,
                                               strlen((const char *)encrypt_private_key_base64));

  // 3.3 Generate Self Encryption Key - AES256
  if ((ret = atchops_aes_generate_key(self_encryption_key_bytes, ATCHOPS_AES_256)) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "Failed Self Encryption Key Generation | ret: %d\n", ret);
    goto def_enc_keypair_free_exit;
  }

  // 3.3.1 base64 encode the SelfEncryptionKey + populate the same into atkeys struct
  size_t self_enc_key_base64_len = 0;
  if ((ret = atchops_base64_encode(self_encryption_key_bytes, aes256_key_unsigned_char_bytes_size,
                                   self_encryption_key_base64, aes256_key_unsigned_char_base64_size,
                                   &self_enc_key_base64_len)) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "Failed encoding SelfEncryptionKey to base64 | ret: %d\n", ret);
    goto def_enc_keypair_free_exit;
  }
  atclient_atkeys_set_self_encryption_key_base64(&atkeys, (const char *)self_encryption_key_base64,
                                                 self_enc_key_base64_len);

  // 3.4 Generate APKAM Symmetric Key - AES256
  if ((ret = atchops_aes_generate_key(apkam_symmetric_key_bytes, ATCHOPS_AES_256)) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "Failed APKAM SymmetricKey Generation\n");
    goto def_enc_keypair_free_exit;
  }

  // 3.4.1 base64 encoding the APKAM symmetric key + populate the same into atkeys struct
  size_t apkam_symm_key_base64_len = 0;
  if ((ret = atchops_base64_encode(apkam_symmetric_key_bytes, aes256_key_unsigned_char_bytes_size,
                                   apkam_symmetric_key_base64, aes256_key_unsigned_char_base64_size,
                                   &apkam_symm_key_base64_len)) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "Failed encoding APKAM SymmetricKey to base64\n");
    goto def_enc_keypair_free_exit;
  }
  atclient_atkeys_set_apkam_symmetric_key_base64(&atkeys, (const char *)apkam_symmetric_key_base64,
                                                 apkam_symm_key_base64_len);

  /*
   * 4. Encrypt the keys and send the onboarding enrollment request
   */
  // 4.1 Encrypt default_encryption_private_key with APKAM Symmetric Key
  size_t encrypted_def_encrypt_private_key_bytes_len = 0;
  if ((ret = atchops_aes_ctr_encrypt(
           apkam_symmetric_key_bytes, ATCHOPS_AES_256, iv, encrypt_private_key_base64,
           strlen((char *)encrypt_private_key_base64), encrypted_default_encryption_private_key_bytes,
           aes256_encrypted_rsa_privkey_unsigned_char_size, &encrypted_def_encrypt_private_key_bytes_len)) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "AES encrypt default_encryption_private_key failed | ret: %d\n",
                 ret);
    goto def_enc_keypair_free_exit;
  }

  // 4.1.1 Base64 encode the encrypted_default_encryption_private_key
  size_t encrypted_default_encryption_private_key_base64_len = 0;
  if ((ret = atchops_base64_encode(encrypted_default_encryption_private_key_bytes,
                                   encrypted_def_encrypt_private_key_bytes_len,
                                   encrypted_default_encryption_private_key_base64,
                                   sizeof(unsigned char) * aes256_encrypted_rsa_2048_privkey_base64_len,
                                   &encrypted_default_encryption_private_key_base64_len)) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR,
                 "base64 encode encrypted_default_encryption_private_key failed | ret: %d\n", ret);
    goto def_enc_keypair_free_exit;
  }

  // 4.2 Encrypt self_encryption_key with APKAM Symmetric Key
  size_t encrypted_self_encrypt_key_bytes_len = 0;
  if ((ret = atchops_aes_ctr_encrypt(apkam_symmetric_key_bytes, ATCHOPS_AES_256, iv, self_encryption_key_base64,
                                     strlen((char *)self_encryption_key_base64), encrypted_self_encryption_key_bytes,
                                     aes256_encrypted_aes256_key_unsigned_char_size,
                                     &encrypted_self_encrypt_key_bytes_len)) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "AES encrypt self_encryption_key failed\tret: %d\n", ret);
    goto def_enc_keypair_free_exit;
  }

  // 4.2.1 Base64 encode the encrypted_self_encryption_key
  size_t encrypted_self_encryption_key_base64_len = 0;
  if ((ret = atchops_base64_encode(encrypted_self_encryption_key_bytes, encrypted_self_encrypt_key_bytes_len,
                                   encrypted_self_encryption_key_base64,
                                   sizeof(unsigned char) * aes256_encrypted_aes_key_base64_len,
                                   &encrypted_self_encryption_key_base64_len)) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "base64 encode encrypted_self_encryption_key failed\tret: %d\n",
                 ret);
    goto def_enc_keypair_free_exit;
  }

  // 4.3 Initialize enrollment params
  atcommons_enroll_params_init(ep);
  ep->app_name = ATAUTH_DEFAULT_FIRST_APP_NAME;
  ep->device_name = ATAUTH_DEFAULT_FIRST_DEVICE_NAME;
  ep->apkam_public_key = (unsigned char *)atkeys.pkam_public_key_base64;
  ep->encrypted_default_encryption_private_key = encrypted_default_encryption_private_key_base64;
  ep->encrypted_self_encryption_key = encrypted_self_encryption_key_base64;

  // 4.4 Send onboarding enrollment request
  if ((ret = atauth_send_enroll_request(&at_client, ep, enrollment_id, status)) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atauth_send_enroll_request: %d\n", ret);
    goto def_enc_keypair_free_exit;
  }
  atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_INFO, "MPKAM enrollment response:\tenrollment_id: %s\tstatus: %s\n",
               enrollment_id, status);

  // 4.5 Populate MPKAM enrollment_id into atkeys struct
  atclient_atkeys_set_enrollment_id(&atkeys, enrollment_id, sizeof(enrollment_id));

  /*
   * 5. Close existing atclient connection
   */
  atclient_connection_disconnect(&at_client.atserver_connection);
  atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_DEBUG, "Terminated existing atserver connection\n");
  /*
   * 6. Perform PKAM auth
   */
  if ((ret = atclient_pkam_authenticate(&at_client, atsign, &atkeys, &options, NULL)) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "PKAM auth failed | atclient_pkam_authenticate: %d\n", ret);
    goto atclient_exit;
  }
  atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_INFO, "PKAM auth success\n");

  /*
   * 7. Update Default Encryption Public Key to server
   */
  atclient_atkey def_enc_pub_atkey;
  atclient_atkey_init(&def_enc_pub_atkey);

  if ((ret = atclient_atkey_create_public_key(&def_enc_pub_atkey, "publickey", atsign, NULL)) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "Failed to create public key\n");
    goto enc_pub_key_free_exit;
  }
  atclient_atkey_metadata_set_is_public(&def_enc_pub_atkey.metadata, true);

  if ((ret = atclient_put_public_key(&at_client, &def_enc_pub_atkey, atkeys.encrypt_public_key_base64, NULL, NULL)) !=
      0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR,
                 "Failed to updating enc_public_key to server | atclient_put_public_key: %d\n", ret);
    goto enc_pub_key_free_exit;
  }

  /*
   * 8. Delete CRAM secret from the server
   */
  atclient_atkey cram_atkey;
  atclient_atkey_init(&cram_atkey);

  if ((ret = atclient_atkey_create_reserved_key(&cram_atkey, "privatekey:at_secret")) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "Failed creating reserved_key: at_secret\n");
    goto cram_atkey_free_exit;
  }

  atclient_delete_request_options delete_request_options;
  atclient_delete_request_options_init(&delete_request_options);
  // skips is_atclient_atkey_is_shared_by_initialized check
  atclient_delete_request_options_set_skip_shared_by_check(&delete_request_options, true);
  if ((ret = atclient_delete(&at_client, &cram_atkey, &delete_request_options, NULL)) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "Failed deleting CRAM Secret\n");
    goto cram_atkey_free_exit;
  }

  /*
   * 9. Write the keys to the .atKeys file
   */
  if ((ret = atclient_atkeys_write_to_path(&atkeys, atkeys_fp)) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atclient_atkeys_write_to_path: %d\n", ret);
    ret = 1;
    goto cram_atkey_free_exit;
  }
  atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_INFO, "Success !!!\t Your atKeys file has been generated at \'%s\'\n",
               atkeys_fp);

  // exits
cram_atkey_free_exit: { atclient_atkey_free(&cram_atkey); }
enc_pub_key_free_exit: { atclient_atkey_free(&def_enc_pub_atkey); }
def_enc_keypair_free_exit: {
  free(encrypt_public_key_base64);
  free(encrypt_private_key_base64);
}
pkam_keypair_free_exit: {
  free(pkam_public_key_base64);
  free(pkam_private_key_base64);
}
atkeys_free_exit: { atclient_atkeys_free(&atkeys); }
atclient_exit: {
  atclient_authenticate_options_free(&options);
  atclient_free(&at_client);
}
atkeys_fp_exit: { free(atkeys_fp); }
args_exit: {
  free(atsign);
  free(cram_secret);
  free(root_host);
}
enroll_params_exit: { free(ep); }
enc_self_enc_key_base64_exit: { free(encrypted_self_encryption_key_base64); }
enc_def_enc_privkey_base64_exit: { free(encrypted_default_encryption_private_key_base64); }
enc_self_enc_key_exit: { free(encrypted_self_encryption_key_bytes); }
enc_def_enc_privkey_exit: { free(encrypted_default_encryption_private_key_bytes); }
aes_keys_bytes_exit: { free(apkam_symmetric_key_bytes); }
self_enc_key_bytes_exit: { free(self_encryption_key_bytes); }
iv_exit: { free(iv); }
exit: {
  if (ret != 0)
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "Aborting with exit code: %d\n", ret);
  exit(ret);
}
}