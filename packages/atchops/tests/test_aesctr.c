#include "atchops/aesctr.h"
#include "atchops/iv.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define PLAINTEXT "I like to eat pizza 123"
#define AES_KEY "1DPU9OP3CYvamnVBMwGgL7fm8yB1klAap0Uc5Z9R79g="

#define BUFFER_SIZE 4096 // 4KB sufficient space to hold ciphertext of encrypted PLAINTEXT and the PLAINTEXT itself

int main(int argc, char **argv) {
  int ret = 1; // error by defaullt

  const char *aeskeybase64 = AES_KEY; // 32 byte key == 256 bits
  const char *plaintext = PLAINTEXT;
  const unsigned long plaintextlen = strlen(plaintext);
  unsigned long olen = 0;

  unsigned char *iv = malloc(sizeof(unsigned char) * ATCHOPS_IV_BUFFER_SIZE);
  memset(iv, 0, ATCHOPS_IV_BUFFER_SIZE);

  unsigned long ciphertextlen = BUFFER_SIZE; // sufficient allocation
  unsigned char *ciphertext = malloc(sizeof(unsigned char) * ciphertextlen);
  memset(ciphertext, 0, ciphertextlen);

  ret = atchops_aesctr_encrypt(aeskeybase64, strlen(aeskeybase64), ATCHOPS_AES_256, iv, (unsigned char *)plaintext,
                               plaintextlen, ciphertext, ciphertextlen, &olen);
  // printf("encrypted (%lu): \"%.*s\"\n", olen, (int) olen, ciphertext);
  if (ret != 0) {
    printf("atchops_aesctr_encrypt (failed): %d\n", ret);
    goto exit;
  }

  unsigned long plaintextlen2 = BUFFER_SIZE; // sufficient allocation
  unsigned char *plaintext2 = malloc(sizeof(unsigned char) * plaintextlen2);
  memset(plaintext2, 0, plaintextlen2);
  memset(iv, 0, 16);
  ret = atchops_aesctr_decrypt(aeskeybase64, strlen(aeskeybase64), ATCHOPS_AES_256, iv, ciphertext, olen, plaintext2,
                               plaintextlen2, &olen);
  // printf("decrypted (%lu) %.*s\n", olen, (int) olen, plaintext2);
  if (ret != 0) {
    printf("atchops_aesctr_decrypt (failed): %d\n", ret);
    goto exit;
  }

  goto exit;

exit: {
  free(iv);
  free(ciphertext);
  free(plaintext2);
  return ret;
}
}
