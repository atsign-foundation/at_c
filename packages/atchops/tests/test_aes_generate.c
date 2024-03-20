#include "atchops/aes.h"
#include "atchops/aesctr.h"
#include "atchops/iv.h"
#include <stdio.h>
#include <string.h>
#include <stddef.h>

#define PLAINTEXT "Hello World!\n"

int main() {

  int ret = 1;

  const size_t keybase64len = 4096;
  unsigned char keybase64[keybase64len];
  memset(keybase64, 0, keybase64len);
  size_t keybase64olen = 0;

  const size_t ciphertextlen = 4096;
  unsigned char ciphertext[ciphertextlen];
  memset(ciphertext, 0, sizeof(unsigned char) * ciphertextlen);
  size_t ciphertextolen = 0;

  unsigned char iv[ATCHOPS_IV_BUFFER_SIZE];

  const size_t plaintext2len = 4096;
  unsigned char plaintext2[plaintext2len];
  memset(plaintext2, 0, sizeof(unsigned char) * plaintext2len);
  size_t plaintext2olen = 0;

  ret = atchops_aes_generate_keybase64(keybase64, keybase64len, &keybase64olen, ATCHOPS_AES_256);
  if (ret != 0) {
    printf("Error generating key\n");
    printf("keybase64: %.*s\n", (int)keybase64olen, keybase64);
    goto exit;
  }

  if (keybase64olen == 0) {
    printf("keybase64olen is %lu\n", keybase64olen);
    ret = 1;
    goto exit;
  }

  if (strlen((char *)keybase64) != keybase64olen) {
    printf("keybase64olen is %lu when it should be %lu\n", keybase64olen, strlen((char *)keybase64));
    ret = 1;
    goto exit;
  }

  printf("key %lu: %s\n", strlen((char *)keybase64), keybase64);

  memset(iv, 0, sizeof(unsigned char) * ATCHOPS_IV_BUFFER_SIZE);
  ret = atchops_aesctr_encrypt((char *)keybase64, keybase64olen, ATCHOPS_AES_256, iv, (const unsigned char *)PLAINTEXT,
                               strlen(PLAINTEXT), ciphertext, ciphertextlen, &ciphertextolen);
  if (ret != 0) {
    printf("Error encrypting\n");
    printf("ciphertext: %.*s\n", (int)ciphertextolen, ciphertext);
    goto exit;
  }

  if (ciphertextolen == 0) {
    printf("ciphertextolen is %lu\n", ciphertextolen);
    ret = 1;
    goto exit;
  }

  if (strlen((char *)ciphertext) != ciphertextolen) {
    printf("ciphertextolen is %lu when it should be %lu\n", ciphertextolen, strlen((char *)ciphertext));
    ret = 1;
    goto exit;
  }

  memset(iv, 0, sizeof(unsigned char) * ATCHOPS_IV_BUFFER_SIZE);
  ret = atchops_aesctr_decrypt((char *)keybase64, keybase64olen, ATCHOPS_AES_256, iv, ciphertext, ciphertextolen,
                               plaintext2, plaintext2len, &plaintext2olen);
  if (ret != 0) {
    printf("Error decrypting\n");
    goto exit;
  }

  printf("plaintext2: %s\n", plaintext2);

  ret = 0;
  goto exit;

exit: { return ret; }
}
