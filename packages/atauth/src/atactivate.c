#include "atauth/atactivate_arg_parser.h"
#include "atauth/atauth_build_atkeys_file_path.h"
#include "atchops/base64.h"
#include "atclient/atclient.h"
#include <atauth/send_enroll_request.h>
#include <atchops/aes.h>
#include <atchops/aes_ctr.h>
#include <atchops/iv.h>
#include <atcommons/enroll_status.h>
#include <atlogger/atlogger.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>

#define TAG "atactivate"

#define FIRST_APP_NAME "firstApp"
#define FIRST_DEVICE_NAME "firstDevice"
// includes padding
#define AES_256_KEY_LEN_BASE64 atchops_base64_encoded_size(ATCHOPS_AES_256)
#define AES_256_KEY_BYTES 32
#define RSA_2048_PRIVKEY_LEN_BYTES 1300 // in PKCS#8 format includes padding
#define RSA_2048_PRIVKEY_LEN_BASE64 atchops_base64_encoded_size(RSA_2048_PRIVKEY_LEN_BYTES)
int main(int argc, char *argv[]) {

  atlogger_set_logging_level(ATLOGGER_LOGGING_LEVEL_DEBUG);

  int ret = 0;
  char *atsign = NULL, *cram_secret = NULL, *root_host = NULL;
  int *root_port = NULL;
  char enrollment_id[ENROLL_ID_MAX_LEN];
  char status[ENROLL_STATUS_STRING_MAX_LEN];
  // intialize iv used for aes encryption of keys
  const size_t iv_size = ATCHOPS_IV_BUFFER_SIZE;
  unsigned char iv[iv_size];

  // initialize apkam symmetric key and self encryption key
  unsigned char self_encryption_key_bytes[AES_256_KEY_BYTES];
  unsigned char apkam_symmetric_key_bytes[AES_256_KEY_BYTES];
  memset(self_encryption_key_bytes, 0, sizeof(self_encryption_key_bytes));
  memset(apkam_symmetric_key_bytes, 0, sizeof(apkam_symmetric_key_bytes));

  // initialize base64 encoded apkam symmetric key and self encryption key
  size_t aes_key_base64_size = sizeof(unsigned char) * AES_256_KEY_LEN_BASE64;
  unsigned char self_encryption_key_base64[aes_key_base64_size];
  unsigned char apkam_symmetric_key_base64[aes_key_base64_size];
  memset(self_encryption_key_base64, 0, sizeof(self_encryption_key_base64));
  memset(apkam_symmetric_key_base64, 0, sizeof(apkam_symmetric_key_base64));

  // intialize encrypted APKAM symmetric Key and encrypted default encryption private key
  const size_t aes256_encrypted_rsa_private_key_size = 256;
  const size_t aes256_encrypted_aes256_key_size = 48;
  unsigned char encrypted_default_encryption_private_key[aes256_encrypted_rsa_private_key_size];
  unsigned char encrypted_self_encryption_key[aes256_encrypted_aes256_key_size];
  memset(encrypted_default_encryption_private_key, 0, sizeof(encrypted_default_encryption_private_key));
  memset(encrypted_self_encryption_key, 0, sizeof(encrypted_self_encryption_key));

  // intialize base64 encoded encrypted APKAM symmetric Key and encrypted default encryption private key
  size_t encrypted_rsa_key_base64_size = atchops_base64_encoded_size(RSA_2048_PRIVKEY_LEN_BYTES);
  size_t encrypted_aes_key_base64_size = atchops_base64_encoded_size(AES_256_KEY_LEN_BASE64);
  char encrypted_default_encryption_private_key_base64[encrypted_rsa_key_base64_size];
  char encrypted_self_encryption_key_base64[encrypted_aes_key_base64_size];
  memset(encrypted_default_encryption_private_key_base64, 0, sizeof(encrypted_default_encryption_private_key_base64));
  memset(encrypted_self_encryption_key_base64, 0, sizeof(encrypted_self_encryption_key_base64));

  enroll_params_t *ep = malloc(sizeof(enroll_params_t)); // Allocate enrollment params
  memset(ep, 0, sizeof(ep));

  if ((ret = atactivate_parse_args(argc, argv, &atsign, &cram_secret, &root_host, &root_port)) != 0) {
    exit(ret);
  }

  // calculate and init mem for atkeys file path
  // initializing this here as atsign is needed to calculate the atkeys_path length
  size_t atkeys_fp_size = 1024;
  // atauth_build_atkeys_file_path(NULL, &atkeys_fp_size, atsign); //fix this
  char atkeys_fp[atkeys_fp_size];

  /*
   * 2. init atclient and CRAM auth
   */
  atclient atclient;
  atclient_init(&atclient);

  atclient_authenticate_options options;
  atclient_authenticate_options_init(&options);

  if ((ret = atclient_cram_authenticate(&atclient, atsign, cram_secret, &options))) {
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
                                             strlen(pkam_public_key_base64));
  atclient_atkeys_set_pkam_private_key_base64(&atkeys, (const char *)pkam_private_key_base64,
                                              strlen(pkam_private_key_base64));
  // populate the pkam keypair into the atclient_keys from the above generated base64 format
  atclient_atkeys_populate_pkam_public_key(&atkeys, (const char *)pkam_public_key_base64,
                                           strlen(pkam_public_key_base64));
  atclient_atkeys_populate_pkam_private_key(&atkeys, (const char *)pkam_private_key_base64,
                                            strlen(pkam_private_key_base64));

  // 3.2 Generate Default Encryption Keypair - RSA2048
  unsigned char *encrypt_public_key_base64 = NULL, *encrypt_private_key_base64 = NULL;
  if ((ret = atchops_rsa_key_generate_base64(&encrypt_public_key_base64, &encrypt_private_key_base64))) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "Failed Default Encryption Keypair Generation\n");
    goto exit;
  }
  atclient_atkeys_set_encrypt_public_key_base64(&atkeys, (const char *)encrypt_public_key_base64,
                                                strlen(encrypt_public_key_base64));
  atclient_atkeys_set_encrypt_private_key_base64(&atkeys, (const char *)encrypt_private_key_base64,
                                                 strlen(encrypt_private_key_base64));
  // populate the encryption keypair into the atclient_keys from the above generated base64 format
  atclient_atkeys_populate_encrypt_public_key(&atkeys, (const char *)encrypt_public_key_base64,
                                              strlen(encrypt_public_key_base64));
  atclient_atkeys_populate_encrypt_private_key(&atkeys, (const char *)encrypt_private_key_base64,
                                               strlen(encrypt_private_key_base64));

  // 3.3 Generate Self Encryption Key - AES256
  if ((ret = atchops_aes_generate_key(self_encryption_key_bytes, ATCHOPS_AES_256))) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "Failed Self Encryption Key Generation\n");
    goto exit;
  }
  // 3.3.1 base64 encode the SelfEncryptionKey
  size_t self_enc_key_base64_len = 0;
  if ((ret = atchops_base64_encode(self_encryption_key_bytes, sizeof(self_encryption_key_bytes),
                                   &self_encryption_key_base64, aes_key_base64_size, &self_enc_key_base64_len)) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "Failed encoding SelfEncryptionKey to base64\n");
    goto exit;
  }
  atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_DEBUG, "base64 len: %lu \tself-en-key: %s\n", self_enc_key_base64_len, self_encryption_key_base64);
  atclient_atkeys_set_self_encryption_key_base64(&atkeys, &self_encryption_key_base64, self_enc_key_base64_len);

  // 3.4 Generate APKAM Symmetric Key - AES256
  if ((ret = atchops_aes_generate_key(apkam_symmetric_key_bytes, ATCHOPS_AES_256))) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "Failed APKAM SymmetricKey Generation\n");
    goto exit;
  }
  // 3.4.1 base64 encoding the APKAM symmetric key
  size_t apkam_symm_key_base64_len = 0;
  if ((ret = atchops_base64_encode(apkam_symmetric_key_bytes, sizeof(apkam_symmetric_key_bytes),
                                   &apkam_symmetric_key_base64, aes_key_base64_size, &apkam_symm_key_base64_len)) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "Failed encoding APKAM SymmetricKey to base64\n");
    goto exit;
  }
  atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_DEBUG, "base64 len: %lu \tapkam-symm-key: %s\n", apkam_symm_key_base64_len, apkam_symmetric_key_base64);
  atclient_atkeys_set_apkam_symmetric_key_base64(&atkeys, &apkam_symmetric_key_base64, apkam_symm_key_base64_len);

  /*
   * 4. Encrypt the keys and send the onboarding enrollment request
   */

  // Encrypt default_encryption_private_key with APKAM Symmetric Key
  memset(iv, 0, sizeof(iv));
  size_t encrypted_def_encrypt_private_key_len = 0;
  if ((ret = atchops_aes_ctr_encrypt(
           apkam_symmetric_key_bytes, ATCHOPS_AES_256, &iv, encrypt_private_key_base64,
           strlen(encrypt_private_key_base64), &encrypted_default_encryption_private_key,
           sizeof(encrypted_default_encryption_private_key), &encrypted_def_encrypt_private_key_len)) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "AES encrypt default_encryption_private_key failed\tret: %d\n", ret);
    goto exit;
  }
  atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_DEBUG, "base64 len: %lu \tencrypted def enc priv key: %s\n", encrypted_def_encrypt_private_key_len, encrypted_default_encryption_private_key);


  // Base64 encode the encrypted_default_encryption_private_key
  size_t encrypted_default_encryption_private_key_base64_len = 0;
  if ((ret = atchops_base64_encode(&encrypted_default_encryption_private_key, encrypted_def_encrypt_private_key_len,
                                   &encrypted_default_encryption_private_key_base64,
                                   sizeof(encrypted_default_encryption_private_key_base64),
                                   &encrypted_default_encryption_private_key_base64_len)) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR,
                 "base64 encode encrypted_default_encryption_private_key failed\tret: %d\n",ret);
    goto exit;
  }

  // Encrypt self_encryption_key with APKAM Symmetric Key
  memset(iv, 0, sizeof(iv));
  size_t encrypted_self_encrypt_key_len = 0;
  if ((ret = atchops_aes_ctr_encrypt(&apkam_symmetric_key_bytes, ATCHOPS_AES_256, &iv, &self_encryption_key_base64,
                                     strlen(self_encryption_key_base64), &encrypted_self_encryption_key,
                                     sizeof(encrypted_self_encryption_key), &encrypted_self_encrypt_key_len)) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "AES encrypt self_encryption_key failed\tret: %d\n", ret);
    goto exit;
  }

  // Base64 encode the encrypted_self_encryption_key
  size_t encrypted_self_encryption_key_base64_len = 0;
  if ((ret = atchops_base64_encode(&encrypted_self_encryption_key, encrypted_self_encrypt_key_len,
                                   &encrypted_self_encryption_key_base64, sizeof(encrypted_self_encryption_key_base64),
                                   &encrypted_self_encryption_key_base64_len)) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "base64 encode encrypted_self_encryption_key failed\tret: %d\n", ret);
    goto exit;
  }

  // Initialize enrollment params
  enroll_params_init(ep);
  ep->app_name = FIRST_APP_NAME;
  ep->device_name = FIRST_DEVICE_NAME;
  ep->apkam_public_key = &atkeys.pkam_public_key_base64;
  ep->encrypted_default_encryption_private_key = &encrypted_default_encryption_private_key_base64;
  ep->encrypted_self_encryption_key = &encrypted_self_encryption_key_base64;

  // Send onboarding enrollment request
  if ((ret = atauth_send_enroll_request(enrollment_id, status, &atclient, ep)) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atauth_send_enroll_request: %d\n", ret);
    goto exit;
  }

  atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_INFO, "MPKAM enrollment response: \n\tenrollment_id: %s\n\tstatus: %s\n",
               enrollment_id, status);

  /*
   * 5. Free existing atclient and re-initialize atclient
   */
  atclient_free(&atclient);
  // should be re-allocated ?
  atclient_init(&atclient);
  atclient_set_atsign(&atclient, atsign);

  atclient_authenticate_options auth_opts;
  atclient_authenticate_options_init(&auth_opts);

  /*
   * 6. Perform APKAM auth
   */
  if ((ret = atclient_pkam_authenticate(&atclient, atsign, &atkeys, &auth_opts)) != 0) {
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

  // remove the debug logs and string conversion after testing
  atclient_atkey_to_string(&atkey, &atkeystr);
  size_t atkeystrlen = strlen(atkeystr);
  atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_DEBUG, "atkeystr.str (%lu): \"%.*s\"\n", atkeystrlen, (int)atkeystrlen,
               atkeystr);
  if ((ret = atclient_put_public_key(&atclient, &atkey, atkeys.encrypt_private_key_base64, NULL, NULL)) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR,
                 "Failed to updating enc_public_key to server | atclient_put_public_key: %d\n", ret);
    goto exit;
  }

  /*
   * 8. Delete CRAM secret from the server
   */
  atclient_atkey_free(&atkey);
  atclient_atkey_init(&atkey);

  if ((ret = atclient_atkey_create_self_key(&atkey, "privatekey:at_secret", NULL, NULL))) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "Failed creating self key: at_secret");
    goto exit;
  }

  // remove the debug logs and string conversion after testing
  atclient_atkey_to_string(&atkey, &atkeystr);
  atkeystrlen = strlen(atkeystr);
  atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_DEBUG, "atkeystr.str (%lu): \"%.*s\"\n", atkeystrlen, (int)atkeystrlen,
               atkeystr);

  if((ret = atclient_delete(&atclient, &atkey, NULL, NULL))) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "Failed deleting CRAM Secret\n");
    goto exit;
  }

  /*
   * 9. Write the keys to the .atKeys file
   */
  atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_INFO, "writing keys into atkeys file\n");
  if((ret = atauth_build_atkeys_file_path(&atkeys_fp, &atkeys_fp_size, atsign) != 0)){
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atauth_build_atkeys_file_path: %d\n", ret);
    goto exit;
  }

  if((ret = atclient_atkeys_write_to_path(&atkeys, &atkeys_fp))) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atclient_atkeys_write_to_path: %d\n", ret);
  }
  atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_INFO, "Success !!!\n Your atKeys file has been generated at \'%s\'\n", atkeys_fp);

exit: {
  if (ret != 0)
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "Aborting\n");

  atclient_authenticate_options_free(&options);
  atclient_free(&atclient);
  free(ep);
  exit(ret);
}
}