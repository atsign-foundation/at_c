#include "atchops/aesctr.h"
#include "atchops/base64.h"
#include "atchops/iv.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stddef.h>

#define PLAINTEXT "I like to eat pizza 123"
#define AESKEY_BASE64 "1DPU9OP3CYvamnVBMwGgL7fm8yB1klAap0Uc5Z9R79g="

#define BUFFER_SIZE 4096 // 4KB sufficient space to hold ciphertext of encrypted PLAINTEXT and the PLAINTEXT itself

int main() {
  int ret = 1; // error by defaullt

  const size_t keysize = 32;
  unsigned char key[keysize];
  memset(key, 0, sizeof(unsigned char) * keysize);
  size_t keylen = 0;

  const size_t ciphertextsize = BUFFER_SIZE; // sufficient allocation
  unsigned char ciphertext[ciphertextsize];
  memset(ciphertext, 0, sizeof(unsigned char) * ciphertextsize);
  size_t ciphertextlen = 0;

  const size_t plaintext2size = BUFFER_SIZE; // sufficient allocation
  unsigned char plaintext2[plaintext2size];
  memset(plaintext2, 0, sizeof(unsigned char) * plaintext2size);
  size_t plaintext2len = 0;

  unsigned char iv[ATCHOPS_IV_BUFFER_SIZE];
  memset(iv, 0, sizeof(unsigned char) * ATCHOPS_IV_BUFFER_SIZE);

  ret = atchops_base64_decode(AESKEY_BASE64, strlen(AESKEY_BASE64), key, keysize, &keylen);
  if(ret != 0) {
    printf("atchops_base64_decode (failed): %d\n", ret);
    goto exit;
  }

  ret = atchops_aesctr_encrypt(key, ATCHOPS_AES_256, iv, (unsigned char *) PLAINTEXT,
                               strlen(PLAINTEXT), ciphertext, ciphertextsize, &ciphertextlen);
  if (ret != 0) {
    printf("atchops_aesctr_encrypt (failed): %d\n", ret);
    goto exit;
  }

  memset(iv, 0, 16);
  ret = atchops_aesctr_decrypt(key, ATCHOPS_AES_256, iv, ciphertext, ciphertextlen, plaintext2,
                               plaintext2size, &plaintext2len);
  // printf("decrypted (%lu) %.*s\n", olen, (int) olen, plaintext2);
  if (ret != 0) {
    printf("atchops_aesctr_decrypt (failed): %d\n", ret);
    goto exit;
  }

  goto exit;

exit: {
  return ret;
}
}
