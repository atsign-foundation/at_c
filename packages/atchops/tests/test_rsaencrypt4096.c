
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

#define RSA_4096_KEY_SIZE 512

#define PUBLICKEYBASE64 "MIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEAjwkaSF12kGH/IGP2xe80" \
"xUY1i5xU+rdrN/PMKVxTnW3bMwlMgzBGeyJb/0M0fC1P1fsedm9U2LH16RT5v1Qr"\
"kZd4WiVrx1+XzGM9AuP+t8kxXMY3WXX1MeacwYDVZlp174phMId34nRkDtqDwFBk"\
"eqJWreo7WpsylLoHExzCztNiHIuAY3c6bltfVyL89bA8OawcFYAIiDuX4VQHJS5D"\
"WWxeC8sXfZZnkg/1n66C/njnkKA8AtP4LlnIVjWvbFpAwenVQ169J1HH8rcchpa8"\
"+JK/nD79cw3E/cw2OwrS0zKuee01F5bm6xYI/WQKpqmMSo1ib1WIfOsQRlcJ2SQv"\
"ZMC+3CgOSpoCzzsrY651MjVeDMskYjE2vpBTVOx6+hTlkfKQBhczqjavUrhghYbx"\
"80pj8d2+rrDPv1PIR+9sV+hQHT/pY8A3JN3iAPwyVSSd1xwWptg/sg/Jx6Nawdgc"\
"+u4njr6iVRBWOd7H9ak8QUJ5majNgMnQCGsjYENy2n5oiamgSeNCAcCB1Z3FXqDK"\
"Txcu2Bv+sy2pcPnx0ykGOQDqz7LiUNEroJ1EFll7xN0BSHiED8fBPAhUh1mKr46L"\
"POh0ZsRxMYI43EpNRlUPvL7pJoWC1nrhmzVlfQPJcNw0lN/9ss3O6LowGg6Q/5e/"\
"t+pNOmY+uaC3DQrVvfTm1H8CAwEAAQ=="

#define PLAINTEXT "banana"

int main() {
  int ret = 1;

  const size_t publickeybase64len = strlen(PUBLICKEYBASE64);
  const char *publickeybase64 = PUBLICKEYBASE64;

  const char *plaintext = PLAINTEXT;
  const size_t plaintextlen = strlen(plaintext);

  const size_t ciphertextsize = RSA_4096_KEY_SIZE;
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

  ret = atchops_rsa_encrypt(&publickey, (const unsigned char *)plaintext, plaintextlen, ciphertext);
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
