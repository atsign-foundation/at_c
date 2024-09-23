
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

exit: {
  atchops_rsa_key_public_key_free(&public_key);
  atchops_rsa_key_private_key_free(&private_key);
  return ret;
}
}