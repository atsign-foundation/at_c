#include "atchops/rsa.h"
#include <mbedtls/md.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <atclient/atkeysfile.h>
#include <atclient/atkeys.h>

#define SIGNATURE_BUFFER_LEN 5000

#define MESSAGE "_4a160d33-0c63-4800-bee0-ee254752f8c8@jeremy_0:6c987cc1-0dde-4ba1-af56-a9677086182"

#define ATKEYSFILE_PATH "/home/realvarx/.atsign/keys/@expensiveferret_key.atKeys"
#define ATSIGN "@expensiveferret"

int main() {

  setbuf(stdout, NULL);
  setbuf(stderr, NULL);

  int ret = 1;

  atclient_atkeysfile atkeysfile;
  atclient_atkeysfile_init(&atkeysfile);
  ret = atclient_atkeysfile_read(&atkeysfile, ATKEYSFILE_PATH);
  if (ret != 0) {
    goto exit;
  }

  // 1b. populate `atkeys` struct
  atclient_atkeys atkeys;
  atclient_atkeys_init(&atkeys);
  ret = atclient_atkeys_populate_from_atkeysfile(&atkeys, atkeysfile);
  // printf("atkeys_populate_code: %d\n", ret);
  if (ret != 0) {
    goto exit;
  }

  unsigned char *signature = calloc(SIGNATURE_BUFFER_LEN, sizeof(unsigned char));
  memset(signature, 0, SIGNATURE_BUFFER_LEN);
  unsigned long signatureolen = 0;

  const char *message = MESSAGE;
  const unsigned long messagelen = strlen(message);

  ret = atchops_rsa_sign(atkeys.pkamprivatekey, MBEDTLS_MD_SHA256, (const unsigned char *)message, messagelen, signature,
                         SIGNATURE_BUFFER_LEN, &signatureolen);
  if (ret != 0) {
    printf("atchops_rsa_sign (failed): %d\n", ret);
    goto exit;
  }

  // ret = memcmp(signature, (const unsigned char *)EXPECTED_SIGNATURE, signatureolen);
  // if (ret != 0) {
  //   printf("memcmp (failed): %d\n", ret);
  //   printf("got: \"%s\" | expected: \"%s\"\n", signature, EXPECTED_SIGNATURE);
  //   goto exit;
  // }
  //
  atchops_rsakey_publickey publickey;
  atchops_rsakey_publickey_init(&publickey);

  ret = atchops_rsakey_populate_publickey(&publickey, PUBLIC_KEY_BASE64, strlen(PUBLIC_KEY_BASE64));
  if (ret != 0) {
    printf("atchops_rsakey_populate_publickey (failed): %d\n", ret);
    goto exit;
  }
  
  ret = atchops_rsa_verify(publickey, MBEDTLS_MD_SHA256, message, messagelen, signature, signatureolen);
  if (ret != 0) {
    printf("atchops_rsakey_verify (failed): %d\n", ret);
    goto exit;
  }

  printf("atchops_rsa_verify (success): %d\n", ret);
  goto exit;

exit: {
  free(signature);
  return ret;
}
}
