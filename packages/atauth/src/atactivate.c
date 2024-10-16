#include <atchops/aes.h>
#include "atchops/base64.h"
#include "atclient/atclient.h"
#include "atauth/atactivate_arg_parser.h"
#include <atlogger/atlogger.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define TAG "atactivate"
#define AES_256_KEY_SIZE 32

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
  printf("Atsign: %s\n", atsign);
  printf("Cram Secret: %s\n", cram_secret);
  printf("Root Server: %s\n", root_host);
  printf("Port: %d\n", root_port);

  /*
   * 2. init atclient and CRAM auth
   */
  atclient_authenticate_options options;
  atclient_authenticate_options_init(&options);

  atclient atclient;
  atclient_init(&atclient);

  if ((ret = atclient_cram_authenticate(&atclient, atsign, cram_secret, &options))) {
    printf('[ERROR] CRAM authentication failed. Please check your CRAM secret and try again\n');
    ret = EXIT_FAILURE;
    goto exit;
  }

  /*
   * 3. Generate APKAM keypair + Default Encryption Keypair + Self encryption key + APKAM Symmetric Key
   */
  atclient_atkeys atkeys;
  atclient_atkeys_init(&atkeys);

  // 3.1 Generate APKAM Keypair - RSA2048
  size_t apkam_pub_key_len = malloc(sizeof(size_t));
  size_t apkam_priv_key_len = malloc(sizeof(size_t));
  if ((ret = atchops_rsa_key_generate(&atkeys.pkam_public_key, &atkeys.pkam_private_key))) {
    printf('[ERROR] Failed APKAM Keypair Generation\n');
    ret = EXIT_FAILURE;
    goto exit;
  }
  // 3.1.1 base64 encode APKAM Public key
  if ((ret = atchops_base64_encode(&atkeys.encrypt_public_key, sizeof(atkeys.encrypt_public_key),
                                   &atkeys.encrypt_public_key_base64, sizeof(atkeys.encrypt_public_key_base64),
                                   &apkam_pub_key_len)) != 0) {
    printf('[ERROR] Failed encoding APKAM PublicKey to base64');
    ret = EXIT_FAILURE;
    goto exit;
  }
  // 3.1.2 base64 encode APKAM Private key
  if ((ret = atchops_base64_encode(&atkeys.encrypt_public_key, sizeof(atkeys.encrypt_public_key),
                                   &atkeys.encrypt_public_key_base64, sizeof(atkeys.encrypt_public_key_base64),
                                   &apkam_pub_key_len)) != 0) {
    printf('[ERROR] Failed encoding APKAM PrivateKey to base64');
    ret = EXIT_FAILURE;
    goto exit;
  }

  // 3.2 Generate Encryption Keypair - RSA2048
  size_t enc_pub_key_len = malloc(sizeof(size_t));
  size_t enc_priv_key_len = malloc(sizeof(size_t));
  if ((ret = atchops_rsa_key_generate(&atkeys.encrypt_public_key, &atkeys.encrypt_private_key))) {
    printf('[ERROR] Failed Default Encryption Keypair Generation\n');
    ret = EXIT_FAILURE;
    goto exit;
  }
  // 3.2.1 base64 encode Encryption Public key
  if ((ret = atchops_base64_encode(&atkeys.encrypt_public_key, sizeof(atkeys.encrypt_public_key),
                                   &atkeys.encrypt_public_key_base64, sizeof(atkeys.encrypt_public_key_base64),
                                   &apkam_pub_key_len)) != 0) {
    printf('[ERROR] Failed encoding Encryption PublicKey to base64');
    ret = EXIT_FAILURE;
    goto exit;
  }
  // 3.2.2 base64 encode Encryption Private key
  if ((ret = atchops_base64_encode(&atkeys.encrypt_public_key, sizeof(atkeys.encrypt_public_key),
                                   &atkeys.encrypt_public_key_base64, sizeof(atkeys.encrypt_public_key_base64),
                                   &apkam_pub_key_len)) != 0) {
    printf('[ERROR] Failed encoding Encryption PrivateKey to base64');
    ret = EXIT_FAILURE;
    goto exit;
  }

  // 3.3 Generate Self EncryptionKey - AES256
  unsigned char self_encryption_key_bytes[AES_256_KEY_SIZE];
  memset(self_encryption_key_bytes, 0, sizeof(unsigned char) * AES_256_KEY_SIZE);
  if ((ret = atchops_aes_generate_key(&self_encryption_key_bytes, ATCHOPS_AES_256))) {
    printf('[ERROR] Failed Self Encryption Key Generation\n');
    ret = EXIT_FAILURE;
    goto exit;
  }
  // 3.3.1 base64 encode the Self EncryptionKey
  size_t self_enc_key_len = malloc(sizeof(size_t));
  if ((ret = atchops_base64_encode(&self_encryption_key_bytes, sizeof(self_encryption_key_bytes),
                                   &atkeys.self_encryption_key_base64, sizeof(atkeys.self_encryption_key_base64),
                                   &self_enc_key_len)) != 0) {
    printf('[ERROR] Failed encoding Encryption PrivateKey to base64');
    ret = EXIT_FAILURE;
    goto exit;
  }

  // 3.4 Generate APKAM SymmetricKey - AES256
  unsigned char apkam_symmetric_key_bytes[AES_256_KEY_SIZE];
  memset(apkam_symmetric_key_bytes, 0, sizeof(unsigned char) * AES_256_KEY_SIZE);
  if ((ret = atchops_aes_generate_key(&self_encryption_key_bytes, ATCHOPS_AES_256))) {
    printf('[ERROR] Failed Self Encryption Key Generation\n');
    ret = EXIT_FAILURE;
    goto exit;
  }
  // 3.4.1 base64 encode the Self EncryptionKey
  size_t apkam_symm_key_len = malloc(sizeof(size_t));
  if ((ret = atchops_base64_encode(&apkam_symmetric_key_bytes, sizeof(apkam_symmetric_key_bytes),
                                   &atkeys.apkam_symmetric_key_base64, sizeof(atkeys.self_encryption_key_base64),
                                   &self_enc_key_len)) != 0) {
    printf('[ERROR] Failed encoding Encryption PrivateKey to base64');
    ret = EXIT_FAILURE;
    goto exit;
                                   }

/*
 * 4. Send onboarding enrollment request - update APKAM public Key + encryptedDefaultSelfEncryptionKey +
 * encryptedDefaultEncryptionPrivateKey + APKAM Symmetric key This step is will fetch the enrollmentId for the
 * firstEnrollment which will be auto approved
 */

/*
 * 5. Perform APKAM auth
 */

/*
 * 6. Update Default Encryption Public Key to server
 */

/*
 * 7. Delete CRAM secret from the server
 */

/*
 * 8. Write the keys to the .atKeys file
 */
exit: {
  // should free the atkeys mem
  // then free the char buffers used to gen aes keys
  exit(ret);
}
}