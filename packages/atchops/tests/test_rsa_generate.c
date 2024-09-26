
#include <atchops/rsa_key.h>
#include <atlogger/atlogger.h>

int main() {

  int ret = 1;

  atlogger_set_logging_level(ATLOGGER_LOGGING_LEVEL_DEBUG);

  atchops_rsa_key_public_key public_key;
  atchops_rsa_key_public_key_init(&public_key);

  atchops_rsa_key_private_key private_key;
  atchops_rsa_key_private_key_init(&private_key);

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

exit: {
  atchops_rsa_key_public_key_free(&public_key);
  atchops_rsa_key_private_key_free(&private_key);
  return ret;
}
}