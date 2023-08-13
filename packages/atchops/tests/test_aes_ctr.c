#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stddef.h>
#include <stdint.h>
#include "atchops/aes_ctr.h"

void printx(const unsigned char *str, size_t len)
{
    for (int i = 0; i < len; i++)
    {
        printf("%02x ", *(str + i));
    }
    printf("\n");
}

int main(int argc, char **argv)
{
    const char *aes_key = "1DPU9OP3CYvamnVBMwGgL7fm8yB1klAap0Uc5Z9R79g="; // 32 byte key == 256 bits
    const char *plaintext = "i like to eat pizza 123";
    const size_t plaintextlen = strlen(plaintext);

    size_t olen = 0;
    // printf("plaintext: ");
    // printf("%s\n", plaintext);
    // printx((const unsigned char *)plaintext, strlen(plaintext));
    // printf("plaintext-len: %lu\n", strlen(plaintext));

    int ret = 1;

    size_t ivlen = 16;
    const unsigned char *iv = malloc(sizeof(unsigned char) * ivlen);
    memset(iv, 0, ivlen);

    size_t ciphertextlen = 1024;
    unsigned char *ciphertext = malloc(sizeof(unsigned char) * ciphertextlen);

    ret = atchops_aes_ctr_encrypt(aes_key, strlen(aes_key), AES_256, iv, ivlen, (const unsigned char *)plaintext, plaintextlen, ciphertext, ciphertextlen, &olen);
    // printf("encrypted: ");
    // printf("%s\n", ciphertext);
    // printx((const unsigned char *)ciphertext, olen);
    // printf("encrypted-len: %lu\n", olen);
    if (ret != 0)
    {
        goto ret;
    }

    size_t plaintextlen2 = 1024;
    unsigned char *plaintext2 = malloc(sizeof(unsigned char) * plaintextlen2);
    memset(iv, 0, 16);
    ret = atchops_aes_ctr_decrypt(aes_key, strlen(aes_key), AES_256, iv, ivlen, (const unsigned char *)ciphertext, ciphertextlen, plaintext2, plaintextlen2, &olen);
    // printf("decrypted: ");
    // printf("%s\n", plaintext2);
    // printx((const unsigned char *) plaintext2, olen);
    // printf("decrypted-len: %lu\n", olen);
    if (ret != 0)
    {
        goto ret;
    }

    free(ciphertext);
    free(plaintext2);
ret:
{
    return ret;
}
}