
#include <atchops/rsa.h>
#include <atchops/rsa_key.h>
#include <atchops/base64.h>
#include <atlogger/atlogger.h>

#define PLAINTEXT "Hello, World!"

static int test2_generate_base64();

int main() {

  int ret = 1;

  atlogger_set_logging_level(ATLOGGER_LOGGING_LEVEL_DEBUG);

  atchops_rsa_key_public_key public_key;
  atchops_rsa_key_public_key_init(&public_key);

  atchops_rsa_key_private_key private_key;
  atchops_rsa_key_private_key_init(&private_key);

  const size_t ciphertext_size = 256;
  unsigned char ciphertext[ciphertext_size];
  memset(ciphertext, 0, sizeof(unsigned char) * ciphertext_size);

  const size_t plaintext_size = 256;
  unsigned char plaintext[plaintext_size];
  memset(plaintext, 0, sizeof(unsigned char) * plaintext_size);

  if ((ret = atchops_rsa_key_generate(&public_key, &private_key)) != 0) {
    atlogger_log("test_rsa_generate", ATLOGGER_LOGGING_LEVEL_ERROR, "Failed to generate RSA key pair\n");
    goto exit;
  }

  // log the public key
  if (atchops_rsa_key_is_public_key_populated(&public_key)) {
    atlogger_log("test_rsa_generate", ATLOGGER_LOGGING_LEVEL_INFO, "Public Key:\n");
    atlogger_log("test_rsa_generate", ATLOGGER_LOGGING_LEVEL_INFO, "N: ");
    for (size_t i = 0; i < public_key.n.len; i++) {
      printf("%02x ", public_key.n.value[i]);
    }
    printf("\n");
    atlogger_log("test_rsa_generate", ATLOGGER_LOGGING_LEVEL_INFO, "E: ");
    for (size_t i = 0; i < public_key.e.len; i++) {
      printf("%02x ", public_key.e.value[i]);
    }
    printf("\n");
  } else {
    atlogger_log("test_rsa_generate", ATLOGGER_LOGGING_LEVEL_ERROR, "Public key is not populated\n");
    goto exit;
  }

  // log the private key
  if (atchops_rsa_key_is_private_key_populated(&private_key)) {
    atlogger_log("test_rsa_generate", ATLOGGER_LOGGING_LEVEL_INFO, "Private Key:\n");
    atlogger_log("test_rsa_generate", ATLOGGER_LOGGING_LEVEL_INFO, "N: ");
    for (size_t i = 0; i < private_key.n.len; i++) {
      printf("%02x ", private_key.n.value[i]);
    }
    printf("\n");
    atlogger_log("test_rsa_generate", ATLOGGER_LOGGING_LEVEL_INFO, "E: ");
    for (size_t i = 0; i < private_key.e.len; i++) {
      printf("%02x ", private_key.e.value[i]);
    }
    printf("\n");
    atlogger_log("test_rsa_generate", ATLOGGER_LOGGING_LEVEL_INFO, "D: ");
    for (size_t i = 0; i < private_key.d.len; i++) {
      printf("%02x ", private_key.d.value[i]);
    }
    printf("\n");
    atlogger_log("test_rsa_generate", ATLOGGER_LOGGING_LEVEL_INFO, "P: ");
    for (size_t i = 0; i < private_key.p.len; i++) {
      printf("%02x ", private_key.p.value[i]);
    }
    printf("\n");
    atlogger_log("test_rsa_generate", ATLOGGER_LOGGING_LEVEL_INFO, "Q: ");
    for (size_t i = 0; i < private_key.q.len; i++) {
      printf("%02x ", private_key.q.value[i]);
    }
    printf("\n");
  } else {
    atlogger_log("test_rsa_generate", ATLOGGER_LOGGING_LEVEL_ERROR, "Private key is not populated\n");
    goto exit;
  }

  // use the public key to encrypt something
  // use the private key to decrypt it

  if ((ret = atchops_rsa_encrypt(&public_key, (const unsigned char *)PLAINTEXT, strlen(PLAINTEXT), ciphertext)) != 0) {
    atlogger_log("test_rsa_generate", ATLOGGER_LOGGING_LEVEL_ERROR, "Failed to encrypt plaintext\n");
    goto exit;
  }

  // log the ciphertext
  atlogger_log("test_rsa_generate", ATLOGGER_LOGGING_LEVEL_INFO, "Ciphertext: ");
  for (size_t i = 0; i < ciphertext_size; i++) {
    printf("%02x ", ciphertext[i]);
  }

  size_t plaintext_len = 0;
  if ((ret = atchops_rsa_decrypt(&private_key, ciphertext, ciphertext_size, plaintext, plaintext_size,
                                 &plaintext_len)) != 0) {
    atlogger_log("test_rsa_generate", ATLOGGER_LOGGING_LEVEL_ERROR, "Failed to decrypt ciphertext\n");
    goto exit;
  }

  // log the plaintext
  atlogger_log("test_rsa_generate", ATLOGGER_LOGGING_LEVEL_INFO, "Plaintext: ");
  for (size_t i = 0; i < plaintext_len; i++) {
    printf("%c", plaintext[i]);
  }
  printf("\n");

  // check if plaintext is equal to PLAINTEXT
  if (strncmp((const char *)plaintext, PLAINTEXT, strlen(PLAINTEXT)) != 0) {
    atlogger_log("test_rsa_generate", ATLOGGER_LOGGING_LEVEL_ERROR, "Plaintext does not match original\n");
    goto exit;
  }

  if((ret = test2_generate_base64())) {
    atlogger_log("test_rsa_generate", ATLOGGER_LOGGING_LEVEL_ERROR, "Failed to test2_generate_base64\n");
    goto exit;
  }

exit: {
  atchops_rsa_key_public_key_free(&public_key);
  atchops_rsa_key_private_key_free(&private_key);
  return ret;
}
}

static int test2_generate_base64() {
  int ret = 1;

  unsigned char *public_key_base64 = NULL;
  unsigned char *private_key_base64 = NULL;

  unsigned char *public_key_base64_decoded = NULL;
  unsigned char *private_key_base64_decoded = NULL;

  atchops_rsa_key_public_key public_key;
  atchops_rsa_key_public_key_init(&public_key);

  atchops_rsa_key_private_key private_key;
  atchops_rsa_key_private_key_init(&private_key);

  const size_t ciphertext_size = 256;
  unsigned char ciphertext[ciphertext_size];
  memset(ciphertext, 0, sizeof(unsigned char) * ciphertext_size);

  const size_t plaintext_size = 256;
  unsigned char plaintext[plaintext_size];
  memset(plaintext, 0, sizeof(unsigned char) * plaintext_size);

  /*
   * 1. test atchops_rsa_key_generate_base64
   */
  if ((ret = atchops_rsa_key_generate_base64(&public_key_base64, &private_key_base64)) != 0) {
    atlogger_log("test_rsa_generate", ATLOGGER_LOGGING_LEVEL_ERROR, "Failed to generate base64 keys\n");
    goto exit;
  }

  const size_t public_key_base64_len = strlen((const char *)public_key_base64);
  const size_t private_key_base64_len = strlen((const char *)private_key_base64);

  atlogger_log("test_rsa_generate", ATLOGGER_LOGGING_LEVEL_INFO, "Public Key Base64 (%lu): %s\n", public_key_base64_len,  public_key_base64);
  atlogger_log("test_rsa_generate", ATLOGGER_LOGGING_LEVEL_INFO, "Private Key Base64 (%lu): %s\n", private_key_base64_len, private_key_base64);

  /*
   * 2. test that we can base 64 decode them
   */

  // 2a. prepare the buffers
  const size_t public_key_base64_decoded_size = atchops_base64_decoded_size(public_key_base64_len);
  if ((public_key_base64_decoded = (unsigned char *)malloc(public_key_base64_decoded_size)) == NULL) {
    atlogger_log("test_rsa_generate", ATLOGGER_LOGGING_LEVEL_ERROR, "Failed to allocate memory for public_key_base64_decoded\n");
    goto exit;
  }
  memset(public_key_base64_decoded, 0, sizeof(unsigned char) * public_key_base64_decoded_size);

  const size_t private_key_base64_decoded_size = atchops_base64_decoded_size(private_key_base64_len);
  if ((private_key_base64_decoded = (unsigned char *)malloc(private_key_base64_decoded_size)) == NULL) {
    atlogger_log("test_rsa_generate", ATLOGGER_LOGGING_LEVEL_ERROR, "Failed to allocate memory for private_key_base64_decoded\n");
    goto exit;
  }
  memset(private_key_base64_decoded, 0, sizeof(unsigned char) * private_key_base64_decoded_size);

  // 2b. decode the base64 strings
  size_t public_key_base64_decoded_len = 0;
  if ((ret = atchops_base64_decode(public_key_base64, public_key_base64_len, public_key_base64_decoded,
                                   public_key_base64_decoded_size, &public_key_base64_decoded_len)) != 0) {
    atlogger_log("test_rsa_generate", ATLOGGER_LOGGING_LEVEL_ERROR, "Failed to decode public_key_base64\n");
    goto exit;
  }

  size_t private_key_base64_decoded_len = 0;
  if ((ret = atchops_base64_decode(private_key_base64, private_key_base64_len, private_key_base64_decoded,
                                   private_key_base64_decoded_size, &private_key_base64_decoded_len)) != 0) {
    atlogger_log("test_rsa_generate", ATLOGGER_LOGGING_LEVEL_ERROR, "Failed to decode private_key_base64\n");
    goto exit;
  }

  // 2c. print
  atlogger_log("test_rsa_generate", ATLOGGER_LOGGING_LEVEL_INFO, "Public Key Base64 Decoded (%lu): ", public_key_base64_decoded_len);
  for (size_t i = 0; i < public_key_base64_decoded_len; i++) {
    atlogger_log(NULL, ATLOGGER_LOGGING_LEVEL_INFO, "%02x ", public_key_base64_decoded[i]);
  }
  atlogger_log(NULL, ATLOGGER_LOGGING_LEVEL_INFO, "\n");

  atlogger_log("test_rsa_generate", ATLOGGER_LOGGING_LEVEL_INFO, "Private Key Base64 Decoded (%lu): ", private_key_base64_decoded_len);
  for (size_t i = 0; i < private_key_base64_decoded_len; i++) {
    atlogger_log(NULL, ATLOGGER_LOGGING_LEVEL_INFO, "%02x ", private_key_base64_decoded[i]);
  }
  atlogger_log(NULL, ATLOGGER_LOGGING_LEVEL_INFO, "\n");

  /*
   * 3. Test that we can use structs
   */

  // 3a. populate the structs
  if ((ret = atchops_rsa_key_populate_public_key(&public_key, (const char *)public_key_base64, public_key_base64_len)) != 0) {
    atlogger_log("test_rsa_generate", ATLOGGER_LOGGING_LEVEL_ERROR, "Failed to populate public key\n");
    goto exit;
  }

  if ((ret = atchops_rsa_key_populate_private_key(&private_key, (const char *)private_key_base64, private_key_base64_len)) != 0) {
    atlogger_log("test_rsa_generate", ATLOGGER_LOGGING_LEVEL_ERROR, "Failed to populate private key\n");
    goto exit;
  }

  // 3b. use it to encrypt the plaintext
  if ((ret = atchops_rsa_encrypt(&public_key, (const unsigned char *)PLAINTEXT, strlen(PLAINTEXT), ciphertext)) != 0) {
    atlogger_log("test_rsa_generate", ATLOGGER_LOGGING_LEVEL_ERROR, "Failed to encrypt plaintext\n");
    goto exit;
  }

  atlogger_log("test_rsa_generate", ATLOGGER_LOGGING_LEVEL_INFO, "Ciphertext: ");
  for (size_t i = 0; i < ciphertext_size; i++) {
    printf("%02x ", ciphertext[i]);
  }
  atlogger_log(NULL, ATLOGGER_LOGGING_LEVEL_INFO, "\n");

  // 3c. decrypt the ciphertext
  size_t plaintext_len = 0;
  if ((ret = atchops_rsa_decrypt(&private_key, ciphertext, ciphertext_size, plaintext, plaintext_size, &plaintext_len)) != 0) {
    atlogger_log("test_rsa_generate", ATLOGGER_LOGGING_LEVEL_ERROR, "Failed to decrypt ciphertext\n");
    goto exit;
  }

  atlogger_log("test_rsa_generate", ATLOGGER_LOGGING_LEVEL_INFO, "Plaintext: ");
  for (size_t i = 0; i < plaintext_len; i++) {
    printf("%c", plaintext[i]);
  }
  atlogger_log(NULL, ATLOGGER_LOGGING_LEVEL_INFO, "\n");

exit: { 
  free(public_key_base64);
  free(private_key_base64);
  free(public_key_base64_decoded);
  free(private_key_base64_decoded);
  atchops_rsa_key_public_key_free(&public_key);
  atchops_rsa_key_private_key_free(&private_key);
  return ret; }
}