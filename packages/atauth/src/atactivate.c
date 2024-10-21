#include "atauth/atactivate_arg_parser.h"
#include "atauth/atauth_build_atkeys_file_path.h"
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

#include <malloc/_malloc.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/syslimits.h>

#define TAG "atactivate"

#define FIRST_APP_NAME "firstApp52"
// #define FIRST_DEVICE_NAME "firstDevice12"
#define FIRST_DEVICE_NAME FIRST_APP_NAME

#define AES_256_KEY_BYTES 32
#define RSA_2048_PRIVKEY_BYTES 1300 // in PKCS#8 format includes padding

int main(int argc, char *argv[]) {
  atlogger_set_logging_level(ATLOGGER_LOGGING_LEVEL_DEBUG);
  atlogger_set_opts(0);

  int ret = 0;
  char *atsign = NULL, *cram_secret = NULL, *root_host = NULL;
  int *root_port = NULL;
  char enrollment_id[ENROLL_ID_MAX_LEN];
  char status[ENROLL_STATUS_STRING_MAX_LEN];

  // intialize iv used for aes encryption of keys
  const size_t iv_size = ATCHOPS_IV_BUFFER_SIZE;
  unsigned char iv[iv_size];

  // initialize apkam symmetric key and self encryption key (bytes)
  unsigned char self_encryption_key_bytes[AES_256_KEY_BYTES] = {0};
  unsigned char apkam_symmetric_key_bytes[AES_256_KEY_BYTES] = {0};

  // initialize base64 encoded apkam symmetric key and self encryption key
  size_t aes_key_base64_size = atchops_base64_encoded_size(AES_256_KEY_BYTES);
  unsigned char self_encryption_key_base64[aes_key_base64_size];
  unsigned char apkam_symmetric_key_base64[aes_key_base64_size];
  memset(self_encryption_key_base64, 0, sizeof(self_encryption_key_base64));
  memset(apkam_symmetric_key_base64, 0, sizeof(apkam_symmetric_key_base64));

  // intialize encrypted APKAM symmetric Key and encrypted default encryption private key (bytes)
  const size_t aes256_encrypted_rsa_private_key_size = 256; // size for an AES256 encrypted RSA2048 privkey in bytes
  const size_t aes256_encrypted_aes256_key_size = 48; // size for an AES256 key encrypted with another AES256 key in bytes
  unsigned char encrypted_default_encryption_private_key[aes256_encrypted_rsa_private_key_size] = {0};
  unsigned char encrypted_self_encryption_key[aes256_encrypted_aes256_key_size] = {0};

  // intialize base64 encoded encrypted APKAM symmetric Key and encrypted default encryption private key
  const size_t rsa_2048_privkey_base64_len = atchops_base64_encoded_size(RSA_2048_PRIVKEY_BYTES);
  const size_t aes256_encrypted_rsa_2048_privkey_base64_len = atchops_base64_encoded_size(rsa_2048_privkey_base64_len);
  const size_t aes256_encrypted_aes_key_base64_len =
      atchops_base64_encoded_size(atchops_base64_encoded_size(ATCHOPS_AES_256));
  unsigned char encrypted_self_encryption_key_base64[aes256_encrypted_aes_key_base64_len];
  unsigned char encrypted_default_encryption_private_key_base64[aes256_encrypted_rsa_2048_privkey_base64_len];
  memset(encrypted_default_encryption_private_key_base64, 0, rsa_2048_privkey_base64_len);
  memset(encrypted_self_encryption_key_base64, 0, sizeof(unsigned char) * aes_key_base64_size);
  
  // allocate memory for atkeys_fp [file path]
  char *atkeys_fp = malloc(sizeof(char) * PATH_MAX);
  memset(atkeys_fp, 0, sizeof(*atkeys_fp));
  if (atkeys_fp == NULL) {
    ret = 1;
    goto exit;
  }

  // allocate memory for enroll params
  enroll_params_t *ep = malloc(sizeof(enroll_params_t)); // Allocate enrollment params
  if (ep == NULL) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "Could not allocate memory for enroll params\n");
    ret = -1;
    goto exit;
  }
  memset(ep, 0, sizeof(*ep));

  /*
  * 1. Parse args
  */
  if ((ret = atactivate_parse_args(argc, argv, &atsign, &cram_secret, &root_host, root_port)) != 0) {
    goto exit;
  }
  // char *atsign = malloc(sizeof(char) * strlen(*temp_atsign) + 1);
  // snprintf(atsign, sizeof(atsign), "%s", temp_atsign);

  /*
   * 2. init atclient and CRAM auth
   */
  atclient at_client;
  atclient_init(&at_client);

  atclient_authenticate_options options;
  atclient_authenticate_options_init(&options);

  if ((ret = atclient_cram_authenticate(&at_client, atsign, cram_secret, &options))) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "CRAM authentication failed\n");
    goto exit;
  }

  /*
   * 3. Generate APKAM keypair + Default Encryption Keypair + Self encryption key + APKAM Symmetric Key
   */
  atclient_atkeys atkeys;
  atclient_atkeys_init(&atkeys);

  // 3.1 Generate APKAM Keypair - RSA2048
  unsigned char *pkam_public_key_base64 = NULL, *pkam_private_key_base64 = NULL;
  if ((ret = atchops_rsa_key_generate_base64(&pkam_public_key_base64, &pkam_private_key_base64))) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "Failed APKAM Keypair Generation\n");
    goto exit;
  }
  atclient_atkeys_set_pkam_public_key_base64(&atkeys, (const char *)pkam_public_key_base64,
                                             strlen((const char *)pkam_public_key_base64));
  atclient_atkeys_set_pkam_private_key_base64(&atkeys, (const char *)pkam_private_key_base64,
                                              strlen((const char *)pkam_private_key_base64));
  // populate the pkam keypair into the atclient_keys from the above generated base64 format
  atclient_atkeys_populate_pkam_public_key(&atkeys, (const char *)pkam_public_key_base64,
                                           strlen((const char *)pkam_public_key_base64));
  atclient_atkeys_populate_pkam_private_key(&atkeys, (const char *)pkam_private_key_base64,
                                            strlen((const char *)pkam_private_key_base64));

  // 3.2 Generate Default Encryption Keypair - RSA2048
  unsigned char *encrypt_public_key_base64 = NULL, *encrypt_private_key_base64 = NULL;
  if ((ret = atchops_rsa_key_generate_base64(&encrypt_public_key_base64, &encrypt_private_key_base64))) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "Failed Default Encryption Keypair Generation\n");
    goto exit;
  }
  atclient_atkeys_set_encrypt_public_key_base64(&atkeys, (const char *)encrypt_public_key_base64,
                                                strlen((const char *)encrypt_public_key_base64));
  atclient_atkeys_set_encrypt_private_key_base64(&atkeys, (const char *)encrypt_private_key_base64,
                                                 strlen((const char *)encrypt_private_key_base64));
  // populate the encryption keypair into the atclient_keys from the above generated base64 format
  atclient_atkeys_populate_encrypt_public_key(&atkeys, (const char *)encrypt_public_key_base64,
                                              strlen((const char *)encrypt_public_key_base64));
  atclient_atkeys_populate_encrypt_private_key(&atkeys, (const char *)encrypt_private_key_base64,
                                               strlen((const char *)encrypt_private_key_base64));

  // 3.3 Generate Self Encryption Key - AES256
  if ((ret = atchops_aes_generate_key(self_encryption_key_bytes, ATCHOPS_AES_256))) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "Failed Self Encryption Key Generation\n");
    goto exit;
  }
  // 3.3.1 base64 encode the SelfEncryptionKey + populate the same into atkeys struct
  size_t self_enc_key_base64_len = 0;
  if ((ret = atchops_base64_encode(self_encryption_key_bytes, sizeof(self_encryption_key_bytes),
                                   self_encryption_key_base64, aes_key_base64_size, &self_enc_key_base64_len)) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "Failed encoding SelfEncryptionKey to base64\n");
    goto exit;
  }
  atclient_atkeys_set_self_encryption_key_base64(&atkeys, (const char *)&self_encryption_key_base64, self_enc_key_base64_len);

  // 3.4 Generate APKAM Symmetric Key - AES256
  if ((ret = atchops_aes_generate_key(apkam_symmetric_key_bytes, ATCHOPS_AES_256))) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "Failed APKAM SymmetricKey Generation\n");
    goto exit;
  }
  // 3.4.1 base64 encoding the APKAM symmetric key + populate the same into atkeys struct
  size_t apkam_symm_key_base64_len = 0;
  if ((ret = atchops_base64_encode(apkam_symmetric_key_bytes, sizeof(apkam_symmetric_key_bytes),
                                   apkam_symmetric_key_base64, aes_key_base64_size, &apkam_symm_key_base64_len)) !=
      0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "Failed encoding APKAM SymmetricKey to base64\n");
    goto exit;
  }
  atclient_atkeys_set_apkam_symmetric_key_base64(&atkeys, &apkam_symmetric_key_base64, apkam_symm_key_base64_len);

  /*
   * 4. Encrypt the keys and send the onboarding enrollment request
   */

  // 4.1 Encrypt default_encryption_private_key with APKAM Symmetric Key
  memset(iv, 0, sizeof(iv));
  size_t encrypted_def_encrypt_private_key_len = 0;
  if ((ret = atchops_aes_ctr_encrypt(
           apkam_symmetric_key_bytes, ATCHOPS_AES_256, iv, encrypt_private_key_base64,
           strlen((const char *)encrypt_private_key_base64), encrypted_default_encryption_private_key,
           sizeof(encrypted_default_encryption_private_key), &encrypted_def_encrypt_private_key_len)) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "AES encrypt default_encryption_private_key failed | ret: %d\n",
                 ret);
    goto exit;
  }

  // 4.1.1 Base64 encode the encrypted_default_encryption_private_key
  size_t encrypted_default_encryption_private_key_base64_len = 0;
  if ((ret = atchops_base64_encode(encrypted_default_encryption_private_key, encrypted_def_encrypt_private_key_len,
                                   encrypted_default_encryption_private_key_base64,
                                   sizeof(encrypted_default_encryption_private_key_base64),
                                   &encrypted_default_encryption_private_key_base64_len)) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR,
                 "base64 encode encrypted_default_encryption_private_key failed | ret: %d\n", ret);
    goto exit;
  }

  // 4.2 Encrypt self_encryption_key with APKAM Symmetric Key
  memset(iv, 0, sizeof(iv));
  size_t encrypted_self_encrypt_key_len = 0;
  if ((ret = atchops_aes_ctr_encrypt(apkam_symmetric_key_bytes, ATCHOPS_AES_256, iv, self_encryption_key_base64,
                                     strlen((const char *)self_encryption_key_base64), encrypted_self_encryption_key,
                                     sizeof(encrypted_self_encryption_key), &encrypted_self_encrypt_key_len)) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "AES encrypt self_encryption_key failed\tret: %d\n", ret);
    goto exit;
  }

  // 4.2.1 Base64 encode the encrypted_self_encryption_key
  size_t encrypted_self_encryption_key_base64_len = 0;
  if ((ret = atchops_base64_encode(encrypted_self_encryption_key, encrypted_self_encrypt_key_len,
                                   encrypted_self_encryption_key_base64, sizeof(encrypted_self_encryption_key_base64),
                                   &encrypted_self_encryption_key_base64_len)) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "base64 encode encrypted_self_encryption_key failed\tret: %d\n",
                 ret);
    goto exit;
  }

  // 4.3 Initialize enrollment params
  enroll_params_init(ep);
  ep->app_name = FIRST_APP_NAME;
  ep->device_name = FIRST_DEVICE_NAME;
  ep->apkam_public_key = (unsigned char *)&atkeys.pkam_public_key_base64;
  ep->encrypted_default_encryption_private_key = (unsigned char *)&encrypted_default_encryption_private_key_base64;
  ep->encrypted_self_encryption_key = (unsigned char *)&encrypted_self_encryption_key_base64;

  // 4.4 Send onboarding enrollment request
  if ((ret = atauth_send_enroll_request(enrollment_id, status, &at_client, ep)) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atauth_send_enroll_request: %d\n", ret);
    goto exit;
  }
  atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_INFO, "MPKAM enrollment response:\tenrollment_id: %s\tstatus: %s\n",
               enrollment_id, status);

  // 4.5 Populate MPKAM enrollment_id into atkeys struct
  atclient_atkeys_set_enrollment_id(&atkeys, enrollment_id, sizeof(enrollment_id));

  /*
   * 5. Close existing atclient connection
   */
  atclient_connection_disconnect(&at_client.atserver_connection);
  atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_DEBUG, "terminated existing atserver connection\n");

  /*
   * 6. Perform APKAM auth
   */
  if ((ret = atclient_pkam_authenticate(&at_client, atsign, &atkeys, &options)) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "PKAM auth failed | atclient_pkam_authenticate: %d\n", ret);
    goto exit;
  }
  atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_INFO, "PKAM auth success\n");

  /*
   * 7. Update Default Encryption Public Key to server
   */
  atclient_atkey atkey;
  atclient_atkey_init(&atkey);
  char *atkeystr = NULL;

  if ((ret = atclient_atkey_create_public_key(&atkey, "publickey", atsign, NULL))) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "Failed to create public key\n");
    goto exit;
  }
  atclient_atkey_metadata_set_is_public(&atkey.metadata, true);

  if ((ret = atclient_put_public_key(&at_client, &atkey, atkeys.encrypt_private_key_base64, NULL, NULL)) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR,
                 "Failed to updating enc_public_key to server | atclient_put_public_key: %d\n", ret);
    goto exit;
  }

  /*
   * 8. Delete CRAM secret from the server
   */
  atclient_atkey_free(&atkey);
  atclient_atkey_init(&atkey);

  if ((ret = atclient_atkey_create_reserved_key(&atkey, "privatekey:at_secret"))) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "Failed creating self key: at_secret\n");
    goto exit;
  }

  atclient_delete_request_options delete_request_options;
  atclient_delete_request_options_init(&delete_request_options);
  atclient_delete_request_options_set_skip_shared_by_check(
      &delete_request_options, true); // skips is_atclient_atkey_is_shared_by_initialized check

  // if ((ret = atclient_delete(&at_client2, &atkey, &delete_request_options, NULL))) {
  //   atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "Failed deleting CRAM Secret\n");
  //   goto cram_delete_exit;
  // }

  /*
   * 9. Write the keys to the .atKeys file
   */
  atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_INFO, "Generating keys into atkeys file\n");
  // if ((ret = atauth_build_atkeys_file_path(atkeys_fp, &atkeys_fp_size, atsign) != 0)) {
  //   atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atauth_build_atkeys_file_path: %d\n", ret);
  //   goto exit;
  // }

  memcpy(atkeys_fp, "/Users/srie/Desktop/keys.atkeys", 32);
  if ((ret = atclient_atkeys_write_to_path(&atkeys, atkeys_fp))) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atclient_atkeys_write_to_path: %d\n", ret);
  }
  atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_INFO, "Success !!!\n Your atKeys file has been generated at \'%s\'\n",
               atkeys_fp);

// exits
cram_delete_exit : { atclient_delete_request_options_free(&delete_request_options); }

exit : {
  if (ret != 0)
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "Aborting\n");

  atclient_authenticate_options_free(&options);
  atclient_free(&at_client);
  if (atsign)
    free(atsign);
  if (cram_secret)
    free(cram_secret);
  if (root_host)
    free(root_host);
  if (atkeys_fp)
    free(atkeys_fp);
  if (ep)
    free(ep);
  free(pkam_public_key_base64);
  free(pkam_private_key_base64);
  free(encrypt_public_key_base64);
  free(encrypt_private_key_base64);
  exit(ret);
}
}