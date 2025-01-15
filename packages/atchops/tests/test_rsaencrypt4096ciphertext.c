#include "atchops/rsa.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stddef.h>
#include <openssl/bio.h>
#include <openssl/evp.h>
#include <openssl/buffer.h>

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
#define EXPECTED_CIPHERTEXT_BASE64 "your_expected_ciphertext_base64_here"

char *base64_encode(const unsigned char *input, int length) {
    BIO *bmem, *b64;
    BUF_MEM *bptr;

    b64 = BIO_new(BIO_f_base64());
    bmem = BIO_new(BIO_s_mem());
    b64 = BIO_push(b64, bmem);
    BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);
    BIO_write(b64, input, length);
    BIO_flush(b64);
    BIO_get_mem_ptr(b64, &bptr);

    char *buff = (char *)malloc(bptr->length + 1);
    memcpy(buff, bptr->data, bptr->length);
    buff[bptr->length] = 0;

    BIO_free_all(b64);

    return buff;
}

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

    char *ciphertext_base64 = base64_encode(ciphertext, ciphertextsize);
    printf("ciphertext (base64 encoded): \"%s\"\n", ciphertext_base64);

    if (strcmp(ciphertext_base64, EXPECTED_CIPHERTEXT_BASE64) == 0) {
        printf("Ciphertext matches expected value.\n");
    } else {
        printf("Ciphertext does not match expected value.\n");
    }

    free(ciphertext_base64);

    goto ret;

ret: {
    return ret;
}
}
