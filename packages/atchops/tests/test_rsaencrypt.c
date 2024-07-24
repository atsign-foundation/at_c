
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

  const size_t ciphertextsize = 1024;
  unsigned char ciphertext[ciphertextsize];
  memset(ciphertext, 0, sizeof(unsigned char) * ciphertextsize);
  size_t ciphertextlen = 0;

  atchops_rsa_key_public_key publickey;
  atchops_rsa_key_public_key_init(&publickey);

  ret = atchops_rsa_key_populate_public_key(&publickey, publickeybase64, publickeybase64len);
  if (ret != 0) {
    printf("atchops_rsa_key_populate_public_key (failed): %d\n", ret);
    goto ret;
  }
  printf("atchops_rsa_key_populate_public_key (success): %d\n", ret);

  ret = atchops_rsa_encrypt(publickey, (const unsigned char *)plaintext, plaintextlen, ciphertext, ciphertextsize,
                            &ciphertextlen);
  if (ret != 0) {
    printf("atchops_rsa_encrypt (failed): %d\n", ret);
    goto ret;
  }
  printf("atchops_rsa_encrypt (success): %d\n", ret);
  printf("ciphertext (base64 encoded): \"%s\"\n", ciphertext);

  goto ret;

ret: {
  return ret;
}
}
