#include "atchops/aesctr.h"
#include <mbedtls/aes.h>
#include <mbedtls/ctr_drbg.h>
#include <mbedtls/entropy.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>

#include <stdio.h> // TODO remove

int atchops_aesctr_encrypt(const unsigned char *key, const enum atchops_aes_size keybits, unsigned char *iv,
                           const unsigned char *plaintext, // plaintext to encrypt
                           const size_t plaintextlen,
                           unsigned char *ciphertext,   // allocated buffer to populate
                           const size_t ciphertextsize, // number of total bytes allocated in the buffer
                           size_t *ciphertextlen        // written actual length in the buffer
) {
  int ret = 1;

  mbedtls_aes_context aes;
  mbedtls_aes_init(&aes);

  // 1. pad the plaintext
  unsigned char *plaintextpadded; // will contain the plaintext with padded trialing bytes
  size_t plaintextpaddedlen;      // the length of the plain text + padding (no null terminator)

  const int numpadbytestoadd = 16 - (plaintextlen % 16);
  const unsigned char padval = numpadbytestoadd;
  // printf("appending %d bytes of padding: 0x%02x\n", numpadbytestoadd, padval);

  plaintextpaddedlen = plaintextlen + numpadbytestoadd;
  // printf("plaintext_paddedlen: %lu = %d + %d\n", plaintextpaddedlen, plaintextlen, numpadbytestoadd);

  plaintextpadded = malloc(sizeof(unsigned char) * (plaintextpaddedlen + 1));
  memcpy(plaintextpadded, plaintext, plaintextlen);
  memset(plaintextpadded + plaintextlen, padval, numpadbytestoadd);
  plaintextpadded[plaintextpaddedlen] = '\0';

  // 2. Initialize AES key
  ret = mbedtls_aes_setkey_enc(&aes, key, keybits);
  if (ret != 0) {
    goto exit;
  }

  // 3. AES CTR Encrypt
  size_t nc_off = 0;
  unsigned char stream_block[16];
  memset(stream_block, 0, sizeof(unsigned char) * 16);
  memset(ciphertext, 0, sizeof(unsigned char) * ciphertextsize); // clear the buffer
  ret = mbedtls_aes_crypt_ctr(&aes, plaintextpaddedlen, &nc_off, iv, stream_block, plaintextpadded, ciphertext);
  if (ret != 0) {
    goto exit;
  }

  *ciphertextlen = plaintextpaddedlen; // ciphertextlen is the same as plaintextpaddedlen, the plaintext (with padding) could be something like 16 bytes long, so the ciphertext will also be 16 bytes long.

  goto exit;

exit: {
  free(plaintextpadded);
  mbedtls_aes_free(&aes);
  return ret;
}
}

int atchops_aesctr_decrypt(const unsigned char *key, const enum atchops_aes_size keybits, unsigned char *iv,
                           const unsigned char *ciphertext, const size_t ciphertextlen, unsigned char *plaintext,
                           const size_t plaintextsize, size_t *plaintextlen) {
  int ret = 1;

  mbedtls_aes_context aes;
  mbedtls_aes_init(&aes);

  size_t nc_off = 0;
  unsigned char *stream_block = malloc(sizeof(unsigned char) * 16);
  memset(stream_block, 0, sizeof(unsigned char) * 16);

  size_t plaintextpaddedsize = plaintextsize + 16;
  unsigned char *plaintextpadded = malloc(sizeof(unsigned char) * plaintextpaddedsize);
  memset(plaintextpadded, 0, plaintextpaddedsize);
  size_t plaintextpaddedlen = 0;

  // 3. AES decrypt
  ret = mbedtls_aes_setkey_enc(&aes, key, keybits);
  if (ret != 0) {
    goto exit;
  }

  ret = mbedtls_aes_crypt_ctr(&aes, ciphertextlen, &nc_off, iv, stream_block, ciphertext, plaintextpadded);
  if (ret != 0) {
    goto exit;
  }

  while (*(plaintextpadded + plaintextpaddedlen++) != '\0')
    ;
  --plaintextpaddedlen; // don't count the null terminator

  // 4. remove padding
  // IBM PKCS Padding method states that there is always at least 1 padded value:
  // https://www.ibm.com/docs/en/zos/2.4.0?topic=rules-pkcs-padding-method the value of the padded byte is always the
  // number of padded bytes to expect, padval == num_padded_bytes
  unsigned char padval = *(plaintextpadded + (plaintextpaddedlen - 1));

  // add null terminator for good sake
  *(plaintextpadded + plaintextpaddedlen - padval) = '\0';

  *plaintextlen = plaintextpaddedlen - padval;
  memcpy(plaintext, plaintextpadded, *plaintextlen);

  goto exit;

exit: {

  // free everything
  free(stream_block);
  free(plaintextpadded);
  mbedtls_aes_free(&aes);

  return ret;
}
}

size_t atchops_aes_ctr_ciphertext_size(const size_t plaintextlen)
{
  return (plaintextlen + 15) & ~0xF;
}

size_t atchops_aes_ctr_plaintext_size(const size_t ciphertextlen)
{
  return (ciphertextlen + 15) & ~0xF;
}
