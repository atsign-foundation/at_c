#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "at_chops/aes_ctr.h"

void printx(const unsigned char *str, size_t len)
{
    for (int i = 0; i < len; i++)
    {
        printf("%02x ", *(str + i));
    }
    printf("\n");
}

int main()
{
    int retval = 0;
    const char *aes_key = "1DPU9OP3CYvamnVBMwGgL7fm8yB1klAap0Uc5Z9R79g="; // 32 byte key
    const char *plaintext = "i like to eat pizza 123 ++ -- //";
    // printf("plaintext: ");
    // printf("%s\n", plaintext);
    // printx((const unsigned char *)plaintext, strlen(plaintext));
    // printf("plaintext-len: %lu\n", strlen(plaintext));

    AESResult *result = malloc(sizeof(AESResult));

    unsigned char *ciphertext = malloc(sizeof(unsigned char) * 1000);

    result = atchops_aes_ctr_encrypt(aes_key, AES_256, (const unsigned char *) plaintext);
    strcpy(ciphertext, result->res);
    // printf("encrypted: ");
    // printf("%s\n", ciphertext);
    // printx((const unsigned char *)ciphertext, strlen(ciphertext));
    // printf("encrypted-len: %lu\n", result->reslen);

    result = atchops_aes_ctr_decrypt(aes_key, AES_256, (const unsigned char *) ciphertext);
    // printf("decrypted: ");
    // printf("%s\n", result->res);
    // printx((const unsigned char *)result->res, result->reslen);
    // printf("decrypted-len: %lu\n", result->reslen);
    retval = strcmp(plaintext, result->res);

    // AESResult *result = atchops_aes256ctr_encrypt()

    return retval;
}