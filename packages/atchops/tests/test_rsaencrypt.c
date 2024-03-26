
#include "atchops/rsa.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stddef.h>

// #define PUBLICKEYBASE64                                                                                                \
//   "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAg3P7mefqZg2GNQPiEHYinmTYUcbbW2Ar9Wi5LCD/"                               \
//   "uRZNRiQJypbAQbpvk6fAo1wh5Ntp1kjPGHrIikUBVREItTkulobOOPVNaC5FUg86kQJ2Wk+ZyPaCIfrto7Gv+"                              \
//   "yn2DiKqjdYdexjmaKbMO90WSZ7yEmC2mq8bRQASD0PoG3RX1skhGkV1FvPbH4OEDuzMxHfGcCvCi3+BPcbgjLIT/dKe2zAHS5/fE9OK1bz+/"       \
//   "FutJTF8M6LKQY8E+h2cQjTEn3RRJlcMp4rwq/0GNmm3mNY5EhUcamKiSWILG9a8nYzeIUafXmESCZk+J1yVu9QcmXP8Dokv+4KLv76/"            \
//   "Y1RsqQIDAQAB"

#define PUBLICKEYBASE64 "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA0puvhTIiwSaqM9j6zPbvgEaj0Byg4AU/mtL5d6j6hnjJt6BDeztfqOxmLz9s+5NYHnS5ZExbtOohlFZXqISI39EWBsKgcqTOgfjCCWj3Cf1BbbNFiz/D322BvT6TLYeMtErSaQYPlQk4i3GZkp2SfwQcJ9CM7Gp+uCHTZ3NxEuU3Ut3roYOhKEVI72XesMPDlf4y8nSAsrpWs9KbU3isflj0yQXqMH3NXbDn2ie7h02Ul+u1fBuRs05TEFfaYt7R5ia+4USvcnkzGtA7mm8Xyo7AF2ZWnWYfx+368936buo7Vu9twt4Xynd/rvMxv2Fc/H/CFN9SI/n6zRN97uf85wIDAQAB"

#define PLAINTEXT "banana"

int main() {
  int ret = 1;

  const size_t publickeybase64len = strlen(PUBLICKEYBASE64);
  const char *publickeybase64 = PUBLICKEYBASE64;

  const char *plaintext = PLAINTEXT;
  const size_t plaintextlen = strlen(plaintext);

  atchops_rsakey_publickey publickey;
  atchops_rsakey_publickey_init(&publickey);

  ret = atchops_rsakey_populate_publickey(&publickey, publickeybase64, publickeybase64len);
  if (ret != 0) {
    printf("atchops_rsakey_populate_publickey (failed): %d\n", ret);
    goto ret;
  }
  printf("atchops_rsakey_populate_publickey (success): %d\n", ret);

  const size_t ciphertextlen = 1024;
  unsigned char *ciphertext = calloc(ciphertextlen, sizeof(unsigned char));
  memset(ciphertext, 0, ciphertextlen);
  size_t ciphertextolen = 0;

  // printf("encrypting...\n");
  ret = atchops_rsa_encrypt(publickey, (const unsigned char *)plaintext, plaintextlen, ciphertext, ciphertextlen,
                            &ciphertextolen);
  if (ret != 0) {
    printf("atchops_rsa_encrypt (failed): %d\n", ret);
    goto ret;
  }
  printf("atchops_rsa_encrypt (success): %d\n", ret);
  printf("ciphertext (base64 encoded): \"%s\"\n", ciphertext);

  goto ret;

ret: {
  free(ciphertext);
  return ret;
}
}
