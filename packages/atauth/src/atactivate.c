#include "atauth/atactivate_arg_parser.h"
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

void main(int argc, char *argv[]) {
  int ret = 0;
  char *atsign, *cram_secret, *root_host;
  int *root_port;
  /*
   * 1. Read args + validate args
   */
  if ((ret = atactivate_parse_args(argc, argv, &atsign, &cram_secret, &root_host, &root_port)) != 0) {
    exit(ret);
  }
  /* Print the values of the arguments */
  printf("Atsign: %s | ", atsign);
  printf("Cram Secret: %s | ", cram_secret);
  printf("Root Server: %s | ", root_host);
  printf("Port: %d\n", root_port);

  /*
   * 2. init atclient and CRAM auth
   */
  atclient atclient;
  atclient_init(&atclient);

  atclient_authenticate_options options;
  atclient_authenticate_options_init(&options);

  if ((ret = atclient_cram_authenticate(&atclient, atsign, cram_secret, &options))) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "CRAM authentication failed. Please check your CRAM secret and try again\n");
    goto exit;
  }

  /*
   * 3. Generate APKAM keypair + Default Encryption Keypair + Self encryption key + APKAM Symmetric Key
   */
  atclient_atkeys atkeys;
  atclient_atkeys_init(&atkeys);

  // 3.1 Generate APKAM Keypair - RSA2048
  const size_t apkam_pub_key_len = 0;
  const size_t apkam_priv_key_len = 0;

  if ((ret = atchops_rsa_key_generate(&atkeys.pkam_public_key, &atkeys.pkam_private_key))) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "Failed APKAM Keypair Generation\n");
    goto exit;
  }
  // 3.1.1 base64 encode APKAM Public key
  if ((ret = atchops_base64_encode(&atkeys.encrypt_public_key, sizeof(atkeys.encrypt_public_key),
                                   &atkeys.encrypt_public_key_base64, sizeof(atkeys.encrypt_public_key_base64),
                                   &apkam_pub_key_len)) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "Failed encoding APKAM PublicKey to base64\n");
    goto exit;
  }
  // 3.1.2 base64 encode APKAM Private key
  if ((ret = atchops_base64_encode(&atkeys.encrypt_public_key, sizeof(atkeys.encrypt_public_key),
                                   &atkeys.encrypt_public_key_base64, sizeof(atkeys.encrypt_public_key_base64),
                                   &apkam_pub_key_len)) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "Failed encoding APKAM PrivateKey to base64\n");
    goto exit;
  }

  // 3.2 Generate Encryption Keypair - RSA2048
  size_t enc_pub_key_len = malloc(sizeof(size_t));
  size_t enc_priv_key_len = malloc(sizeof(size_t));
  if ((ret = atchops_rsa_key_generate(&atkeys.encrypt_public_key, &atkeys.encrypt_private_key))) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "Failed Default Encryption Keypair Generation\n");
    ret = EXIT_FAILURE;
    goto exit;
  }
  // 3.2.1 base64 encode Encryption Public key
  if ((ret = atchops_base64_encode(&atkeys.encrypt_public_key, sizeof(atkeys.encrypt_public_key),
                                   &atkeys.encrypt_public_key_base64, sizeof(atkeys.encrypt_public_key_base64),
                                   &apkam_pub_key_len)) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "Failed encoding Encryption PublicKey to base64\n");
    ret = EXIT_FAILURE;
    goto exit;
  }
  // 3.2.2 base64 encode Encryption Private key
  if ((ret = atchops_base64_encode(&atkeys.encrypt_public_key, sizeof(atkeys.encrypt_public_key),
                                   &atkeys.encrypt_public_key_base64, sizeof(atkeys.encrypt_public_key_base64),
                                   &apkam_pub_key_len)) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "Failed encoding Encryption PrivateKey to base64\n");
    goto exit;
  }

  // 3.3 Generate Self EncryptionKey - AES256
  unsigned char self_encryption_key_bytes[ATCHOPS_AES_256];
  memset(self_encryption_key_bytes, 0, sizeof(unsigned char) * ATCHOPS_AES_256);
  if ((ret = atchops_aes_generate_key(&self_encryption_key_bytes, ATCHOPS_AES_256))) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "Failed Self Encryption Key Generation\n");
    goto exit;
  }
  // 3.3.1 base64 encode the Self EncryptionKey
  size_t self_enc_key_len = malloc(sizeof(size_t));
  if ((ret = atchops_base64_encode(&self_encryption_key_bytes, sizeof(self_encryption_key_bytes),
                                   &atkeys.self_encryption_key_base64, sizeof(atkeys.self_encryption_key_base64),
                                   &self_enc_key_len)) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "Failed encoding SelfEncryptionKey to base64\n");
    goto exit;
  }

  // 3.4 Generate APKAM SymmetricKey - AES256
  unsigned char apkam_symmetric_key_bytes[ATCHOPS_AES_256];
  memset(apkam_symmetric_key_bytes, 0, sizeof(unsigned char) * ATCHOPS_AES_256);
  if ((ret = atchops_aes_generate_key(&apkam_symmetric_key_bytes, ATCHOPS_AES_256))) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "Failed APKAM SymmetricKey Generation\n");
    goto exit;
  }
  // 3.4.1 base64 encode the APKAM SymmetricKey
  size_t apkam_symm_key_len = malloc(sizeof(size_t));
  if ((ret = atchops_base64_encode(&apkam_symmetric_key_bytes, sizeof(apkam_symmetric_key_bytes),
                                   &atkeys.apkam_symmetric_key_base64, sizeof(atkeys.self_encryption_key_base64),
                                   &self_enc_key_len)) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "Failed encoding APKAM SymmetricKey to base64\n");
    goto exit;
  }

  /*
   * 4. Send onboarding enrollment request - update APKAM public Key + encryptedDefaultSelfEncryptionKey +
   * encryptedDefaultEncryptionPrivateKey + APKAM Symmetric key This step is will fetch the enrollmentId for the
   * firstEnrollment which will be auto approved
   */
  const size_t iv_size = ATCHOPS_IV_BUFFER_SIZE;
  unsigned char iv[iv_size];

  const size_t ciphertext_size = 256;

  unsigned char encrypted_default_encryption_private_key[ciphertext_size];
  unsigned char encrypted_self_encryption_key[ciphertext_size];
  size_t encrypted_def_encrypt_private_key_len = 0;
  size_t encrypted_self_encrypt_key_len = 0;

  size_t encrypted_default_encryption_private_key_base64_len = 0, encrypted_self_encryption_key_base64_len = 0;
  size_t encrypted_rsa_key_base64_size = atchops_base64_encoded_size(strlen(&atkeys.encrypt_private_key_base64));
  char encrypted_default_encryption_private_key_base64[encrypted_rsa_key_base64_size];
  size_t encrypted_aes_key_base64_size = atchops_base64_encoded_size(strlen(&atkeys.self_encryption_key_base64));
  char encrypted_self_encryption_key_base64[encrypted_aes_key_base64_size];

  enroll_params_t *ep = malloc(sizeof(enroll_params_t));

  /*
   * 4.1 Encrypt default_encryption_private_key with APKAM Symmetric Key
   */
  memset(iv, 0, sizeof(unsigned char) * iv_size);
  if ((ret = atchops_aes_ctr_encrypt(
           &apkam_symmetric_key_bytes, ATCHOPS_AES_256, iv, &atkeys.encrypt_private_key_base64,
           sizeof(atkeys.encrypt_private_key_base64), &encrypted_default_encryption_private_key,
           sizeof(encrypted_default_encryption_private_key), &encrypted_def_encrypt_private_key_len)) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR,
                 "Could not encrypt default_encryption_private_key with APKAM Symmetric Key\n");
    goto exit;
  }

  /*
   * 4.1.1 base64 encode the encrypted_default_encryption_private_key
   */
  if ((ret = atchops_base64_encode(
           &encrypted_default_encryption_private_key, sizeof(encrypted_default_encryption_private_key),
           encrypted_default_encryption_private_key_base64, sizeof(encrypted_default_encryption_private_key_base64),
           &encrypted_default_encryption_private_key_base64_len)) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR,
                 "Could not base64 encode encrypted_default_encryption_private_key\n");
    goto exit;
  }

  /*
   * 4.2 Encrypt default_encryption_private_key with APKAM Symmetric Key
   */
  memset(iv, 0, sizeof(unsigned char) * iv_size);
  if ((ret =
           atchops_aes_ctr_encrypt(&apkam_symmetric_key_bytes, ATCHOPS_AES_256, iv, &atkeys.self_encryption_key_base64,
                                   sizeof(atkeys.self_encryption_key_base64), &encrypted_self_encryption_key,
                                   sizeof(encrypted_self_encryption_key), &encrypted_self_encrypt_key_len)) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "Could not encrypt self_encryption_key with APKAM Symmetric Key\n");
    goto exit;
  }

  /*
   * 4.2.1 base64 encode the encrypted_default_encryption_private_key
   */
  if ((ret = atchops_base64_encode(&encrypted_self_encryption_key, sizeof(encrypted_self_encryption_key),
                                   encrypted_self_encryption_key_base64, sizeof(encrypted_self_encryption_key_base64),
                                   &encrypted_self_encryption_key_base64_len)) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "Could not base64 encode encrypted_self_encryption_key\n");
    goto exit;
  }

  /*
   * 4.3 Build enroll params struct
   */
  if (!ep) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "Failed to allocate memory for enroll_params_t\n");
    ret = 1;
    goto exit;
  }
  enroll_params_init(ep);

  ep->app_name = FIRST_APP_NAME;
  ep->device_name = FIRST_DEVICE_NAME;
  ep->apkam_public_key = &atkeys.pkam_public_key_base64;
  ep->encrypted_default_encryption_private_key = &encrypted_default_encryption_private_key_base64;
  ep->encrypted_self_encryption_key = &encrypted_self_encryption_key_base64;

  /*
   * 4.4 Send onboarding enrollment request
   */
  char enrollment_id[ENROLL_ID_MAX_LEN];
  char status[ENROLL_STATUS_STRING_MAX_LEN];
  if ((ret = atauth_send_enroll_request(&enrollment_id, &status, &atclient, ep)) != 0) {
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
  if((ret = atclient_pkam_authenticate(&atclient, atsign, &atkeys, &auth_opts)) != 0) {
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

  if((ret = atclient_atkey_create_public_key(&atkey, "publickey", atsign, NULL))) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "Failed to create public key\n");
    goto exit;
  }

  atclient_atkey_metadata_set_is_public(&atkey.metadata, true);

  // remove the debug logs and string conversion after testing
  atclient_atkey_to_string(&atkey, &atkeystr);
  size_t atkeystrlen = strlen(atkeystr);
  atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_DEBUG, "atkeystr.str (%lu): \"%.*s\"\n", atkeystrlen, (int)atkeystrlen,
               atkeystr);
  if((ret = atclient_put_public_key(&atclient, &atkey, atkeys.encrypt_private_key_base64, NULL, NULL)) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "Failed to updating enc_public_key to server | atclient_put_public_key: %d\n", ret);
    goto exit;
  }

  /*
   * 8. Delete CRAM secret from the server
   */
  atclient_atkey_free(&atkey);
  atclient_atkey_init(&atkey);

  if((ret = atclient_atkey_create_self_key(&atkey, "privatekey:at_secret", NULL, NULL))) {
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
   * 8. Write the keys to the .atKeys file
   */
exit: {
  if(ret != 0) printf("Aborting\n");

  // should free the atkeys mem
  // then free the char buffers used to gen aes keys
  atclient_authenticate_options_free(&options);
  atclient_free(&atclient);
  exit(ret);
}
}