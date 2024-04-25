#include "atchops/aes.h"
#include "atchops/aesctr.h"
#include "atchops/iv.h"
#include <stdio.h>
#include <string.h>
#include <stddef.h>

#define PLAINTEXT "Hello World!\n"

int main() {

  int ret = 1;

  const size_t keysize = 32;
  unsigned char key[keysize];
  memset(key, 0, sizeof(unsigned char) * keysize);

  const size_t ciphertextsize = 2048;
  unsigned char ciphertext[ciphertextsize];
  memset(ciphertext, 0, sizeof(unsigned char) * ciphertextsize);
  size_t ciphertextlen = 0;

  unsigned char iv[ATCHOPS_IV_BUFFER_SIZE];

  const size_t plaintext2size = 2048;
  unsigned char plaintext2[plaintext2size];
  memset(plaintext2, 0, sizeof(unsigned char) * plaintext2size);
  size_t plaintext2len = 0;

  ret = atchops_aes_generate_key(key, ATCHOPS_AES_256);
  if (ret != 0) {
    printf("Error generating key\n");
    goto exit;
  }

  memset(iv, 0, sizeof(unsigned char) * ATCHOPS_IV_BUFFER_SIZE);
  ret = atchops_aesctr_encrypt(key, ATCHOPS_AES_256, iv, (const unsigned char *)PLAINTEXT,
                               strlen(PLAINTEXT), ciphertext, ciphertextsize, &ciphertextlen);
  if (ret != 0) {
    printf("Error encrypting\n");
    goto exit;
  }

  if (ciphertextlen == 0) {
    printf("ciphertextolen is %lu\n", ciphertextlen);
    ret = 1;
    goto exit;
  }

  if (strlen((char *)ciphertext) != ciphertextlen) {
    printf("ciphertextolen is %lu when it should be %lu\n", ciphertextlen, strlen((char *)ciphertext));
    ret = 1;
    goto exit;
  }

  memset(iv, 0, sizeof(unsigned char) * ATCHOPS_IV_BUFFER_SIZE);
  ret = atchops_aesctr_decrypt(key, ATCHOPS_AES_256, iv, ciphertext, ciphertextlen,
                               plaintext2, plaintext2size, &plaintext2len);
  if (ret != 0) {
    printf("Error decrypting\n");
    goto exit;
  }

  if(strcmp(PLAINTEXT, (char *)plaintext2) != 0) {
    printf("plaintext2 is \"%.*s\" when it should be \"%s\"\n", (int)plaintext2len, plaintext2, PLAINTEXT);
    ret = 1;
    goto exit;
  }

  ret = 0;
  goto exit;

exit: { return ret; }
}
