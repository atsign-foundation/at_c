#include <atchops/aes_ctr.h>
#include <atchops/base64.h>
#include <atchops/iv.h>
#include <atlogger/atlogger.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define ENCODED_ENCRYPTED_AES_KEY "1xxewcGwphrpyFkDlfwgIjtHxvpqj1Y7v7vDemJgw8Pj7ewUIByzQwnxsfq6FGO"
#define AES_KEY "A6jZvnt89Cj1RuNuHUyUdbFCOjGiY99zGSLaQ5aQ7sI="

int main() {
    atlogger_set_logging_level(ATLOGGER_LOGGING_LEVEL_DEBUG);

    // Decode the encrypted AES key
    size_t encoded_len = strlen(ENCODED_ENCRYPTED_AES_KEY);
    size_t ciph_decoded_len = 0;
    size_t ciph_decoded_size = atchops_base64_decoded_size(encoded_len);
    unsigned char *decoded_encrypted_aes_key = malloc(ciph_decoded_size);

    if (!decoded_encrypted_aes_key ||
        atchops_base64_decode(ENCODED_ENCRYPTED_AES_KEY, encoded_len, decoded_encrypted_aes_key, ciph_decoded_size, &ciph_decoded_len) != 0) {
        fprintf(stderr, "Base64 decoding failed\n");
        free(decoded_encrypted_aes_key);
        return 1;
    }

    printf("Decoded encrypted AES key size: %lu\n", ciph_decoded_size);
    printf("Decoded encrypted AES key length: %lu\n", ciph_decoded_len);

    for (size_t i = 0; i < ciph_decoded_len; i++) {
        printf("%d\t", decoded_encrypted_aes_key[i]);
    }
    printf("\n");

    // Decode the AES key
    encoded_len = strlen(AES_KEY);
    size_t decoded_size = atchops_base64_decoded_size(encoded_len);
  size_t decoded_len = 0;
    unsigned char *aes_key_bytes = malloc(decoded_size);

    if (!aes_key_bytes ||
        atchops_base64_decode(AES_KEY, encoded_len, aes_key_bytes, decoded_size, &decoded_len) != 0) {
        fprintf(stderr, "Base64 decoding of AES key failed\n");
        free(decoded_encrypted_aes_key);
        free(aes_key_bytes);
        return 2;
    }

    printf("Decoded AES key length: %lu\n", decoded_len);

    // Initialize IV
    unsigned char *iv = malloc(ATCHOPS_IV_BUFFER_SIZE);
    if (!iv) {
        fprintf(stderr, "Memory allocation for IV failed\n");
        free(decoded_encrypted_aes_key);
        free(aes_key_bytes);
        return 3;
    }

    // Decrypt the self-encrypted key
    size_t decrypted_size = atchops_aes_ctr_plaintext_size(ciph_decoded_len);
  printf("Decrypted self-encrypted key szie: %lu\n", decrypted_size);
    unsigned char *decrypted_self_enc_key = malloc(decrypted_size);
  size_t decrypted_len = 0;

    if (!decrypted_self_enc_key) {
        fprintf(stderr, "Memory allocation for decrypted key failed\n");
        free(decoded_encrypted_aes_key);
        free(aes_key_bytes);
        free(iv);
        return 4;
    }
    memset(decrypted_self_enc_key, 0, decrypted_size);

    if (atchops_aes_ctr_decrypt(aes_key_bytes, ATCHOPS_AES_256, iv, decoded_encrypted_aes_key, ciph_decoded_len,
                                decrypted_self_enc_key, decrypted_size, &decrypted_len) != 0) {
        fprintf(stderr, "AES decryption failed\n");
        free(decoded_encrypted_aes_key);
        free(aes_key_bytes);
        free(iv);
        free(decrypted_self_enc_key);
        return 5;
    }

    printf("Decrypted self-encrypted key length: %lu\n", decrypted_len);

    for (size_t i = 0; i < decrypted_len; i++) {
        printf("%d\t", decrypted_self_enc_key[i]);
    }
    printf("\n");

    // Cleanup
    free(decoded_encrypted_aes_key);
    free(aes_key_bytes);
    free(iv);
    free(decrypted_self_enc_key);

    return 0;
}
