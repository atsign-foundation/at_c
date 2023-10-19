#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "atchops/aes_ctr.h"

#define PLAINTEXT "I like to eat pizza 123"
#define AES_KEY "1DPU9OP3CYvamnVBMwGgL7fm8yB1klAap0Uc5Z9R79g="

int main(int argc, char **argv)
{
    const unsigned char *aes_key = AES_KEY; // 32 byte key == 256 bits
    const unsigned char *plaintext = PLAINTEXT;
    const unsigned long plaintextlen = strlen(plaintext);
    unsigned long olen = 0;

    // printf("plaintext: ");
    // printf("%s\n", plaintext);
    // printx((const unsigned char *)plaintext, strlen(plaintext));
    // printf("plaintext-len: %lu\n", strlen(plaintext));

    int ret = 1;

    unsigned long ivlen = 16;
    const unsigned char *iv = malloc(sizeof(unsigned char) * ivlen);
    memset(iv, 0, ivlen);

    unsigned long ciphertextlen = 4096;
    unsigned char *ciphertext = malloc(sizeof(unsigned char) * ciphertextlen);

    ret = atchops_aes_ctr_encrypt(aes_key, strlen(aes_key), ATCHOPS_AES_256, iv, ivlen, plaintext, plaintextlen, ciphertext, ciphertextlen, &olen);
    // printf("encrypted: ");
    // printf("%s\n", ciphertext);
    // printx((const unsigned char *)ciphertext, olen);
    // printf("encrypted-len: %lu\n", olen);
    if (ret != 0)
    {
        goto exit;
    }

    size_t plaintextlen2 = 4096;
    unsigned char *plaintext2 = malloc(sizeof(unsigned char) * plaintextlen2);
    memset(iv, 0, 16);
    ret = atchops_aes_ctr_decrypt(aes_key, strlen(aes_key), ATCHOPS_AES_256, iv, ivlen, ciphertext, ciphertextlen, plaintext2, plaintextlen2, &olen);
    // printf("decrypted: ");
    // printf("%s\n", plaintext2);
    // printx((const unsigned char *) plaintext2, olen);
    // printf("decrypted-len: %lu\n", olen);
    if (ret != 0)
    {
        goto exit;
    }

    free(ciphertext);
    free(plaintext2);
    goto exit;

exit:
{
    return ret;
}
}